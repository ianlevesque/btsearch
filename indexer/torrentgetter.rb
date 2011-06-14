require 'rubygems'
require 'eventmachine'
require 'bencode'
require 'socket'
require 'digest'

class TorrentGetter < EventMachine::Connection
  BtHandshake = "\x13BitTorrent protocol"
  BtReservedBits = "\x00\x00\x00\x00\x00\x10\x00\x00"
  PieceSize = 16384
  
  def initialize(infohash)
    if infohash.length == 20
      @hash = infohash
    else
      @hash = [infohash].pack('H*')
    end
    
    @metadata = {}
    set_comm_inactivity_timeout(10)
  end
  
  def callback(&block)
    @callback = block
  end
  
  def errback(&block)
    @errback = block
  end
  
  # Evented methods
  
  def post_init
    $total_connections ||= 0
    $total_connections += 1
    
    send_handshake
    send_extended_handshake
  rescue
    puts $!, $!.backtrace
  end
  
  def receive_data(data)
    # port, ip = Socket.unpack_sockaddr_in(get_peername)
    
    # puts "Got #{data.length} bytes from #{ip}:#{port}"
    
    @buffer ||= "".force_encoding('BINARY')
    loop do
      need = (@next_message_length > 0 ? @next_message_length : 4) - @buffer.length
  
      if data.length < need
        @buffer << data
      
        # puts "Waiting for more data"
        break
      else
        @buffer << data.slice!(0, need)
      
        # puts "#{data.length} bytes left to process"
      end
      
      if @next_message_length == 0
        @next_message_length = @buffer.unpack("N")[0]
        # puts "Next message length: #{@next_message_length}"
        @buffer = "".force_encoding('BINARY')
      else
        if @first_message        
          handle_first_message(@buffer[0, @next_message_length])
      
          @first_message = false
        else
          handle_message(@buffer[0, @next_message_length]) if @next_message_length > 0
        end
        
        @next_message_length = 0
        @buffer = "".force_encoding('BINARY')
      end
    end
  end
  
  # support methods
  def send_handshake
    puts "Handshaking..."
    full_handshake = BtHandshake + BtReservedBits + @hash + random_peer_id
    
    send_data(full_handshake)
    
    @next_message_length = full_handshake.length
    @first_message = true
  end
  
  def send_extended_handshake
    payload = {'m' => {'ut_metadata' => 57}}.bencode
    
    message = [payload.length + 2, 20, 0, payload].pack("NCCA*")
    
    send_data(message)
  end
  
  def random_peer_id
    id = "".force_encoding('BINARY')
    20.times { id << rand(255) }
    id
  end
  
  def handle_first_message(data)
    if data[0, BtHandshake.length] != BtHandshake
      puts "Not a BitTorrent client on the other end: #{data[0...BtHandshake.length][0]}"
      
      fail_and_close
      return
    end
    
    reserved = data[BtHandshake.length, BtReservedBits.length]
    if (reserved.getbyte(5) & 0x10) != 0
      puts "Supports extensions"
      
      hash = data[BtHandshake.length + BtReservedBits.length, 20]
      
      if hash == @hash
        puts "Hash match"
        
        peer_id = data[BtHandshake.length + BtReservedBits.length + 20, 20]
        
        # puts "Remote peer: #{peer_id}"
      else
        puts "Hash mismatch"
        fail_and_close
        return
      end
    else
      puts "Doesn't support extensions"
      fail_and_close
      return
    end
  end
  
  def handle_message(data)
    case data.getbyte(0)
    when 20
      puts "Extension message"
      handle_extension_message(data)
    else
      # puts "Unimplemented message: #{data.getbyte(0)}"      
    end
  end
  
  def handle_extension_message(data)
    case data.getbyte(1)
    when 0
      puts "Supported extensions:"
      
      begin
        dict = BEncode.load(data[2...data.length])
        
        extensions = dict['m']
        
        extensions.each do |ext, code|
          puts "  #{ext} (#{code})"
        end
        
        @ut_metadata_code = extensions['ut_metadata']
        
        if @ut_metadata_code.nil?
          puts "Doesn't support metadata transfer"
          fail_and_close
          return
        end
        
        @metadata_size = dict['metadata_size']
        
        request_pieces
      rescue
        puts "Error getting ut_metadata command code"
        fail_and_close
        return
      end
    when 57
      puts "Metadata message"
      
      dict = BEncode.load(data[2...data.length], :ignore_trailing_junk => true)
      
      case dict['msg_type']
      when 0
        puts "Peer wants a chunk of metadata, rejecting"
        payload = {'msg_type' => 2, 'piece' => dict['piece']}.bencode
        message = [payload.length + 2, 20, @ut_metadata_code, payload].pack("NCCA*")
        send_data(message)
      when 1
        piece_size = dict['total_size']
        piece = dict['piece']
        
        piece_size = data.length - 2 - dict.bencode.length
        
        puts "Got metadata piece #{piece}, #{piece_size} bytes"
        
        piece_data = data.slice(data.length - piece_size, piece_size)
        
        @metadata[piece] = piece_data
        
        check_for_complete_metadata
      when 2
        piece = dict['piece']
        
        puts "Rejected request for metadata piece #{piece}"
      end
    else
      puts "Unknown extension message: #{data.getbyte(1)}"
    end
  end
  
  def request_pieces
    puts "Requesting pieces"
    
    total_pieces = @metadata_size / PieceSize + ((@metadata_size % PieceSize == 0) ? 0 : 1)
    
    total_pieces.times do |next_piece|
      unless @metadata[next_piece]
        puts "Requesting piece #{next_piece+1} / #{total_pieces}"
        payload = {'msg_type' => 0, 'piece' => next_piece}.bencode
        message = [payload.length + 2, 20, @ut_metadata_code, payload].pack("NCCA*")
        send_data(message)
      else
        puts "Already have piece #{next_piece}"
      end
    end
  end
  
  def fail_and_close
    @errback.call if @errback
    
    close_connection
  end
  
  def check_for_complete_metadata
    size = 0
    last_piece = 0
    
    @metadata.each do |number, piece|
      last_piece = [number, last_piece].max
      
      size += piece.length
    end
    
    if size == @metadata_size
      puts "Metadata complete"
      
      torrent_info = "".force_encoding('BINARY')
      
      (0..last_piece).each do |piece|
        torrent_info << @metadata[piece]
      end
      
      raise unless torrent_info.length == size
      
      if Digest::SHA1.digest(torrent_info)
        puts "Valid and complete metadata"
        
        @callback.call(torrent_info) if @callback
        
        @finished = true
        close_connection
      else
        puts "Invalid metadata"
        fail_and_close
      end
    end
  end
  
  def unbind
    $total_connections -= 1
  
    puts "Connection closed (#{$total_connections} remain)"
    
    @errback.call unless @finished
  end
end
