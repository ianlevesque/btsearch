require 'rubygems'
require 'eventmachine'
require 'bencode'

module TorrentIndexer
  @@known_infohashes = {}
  
  def receive_data data
    packet = BEncode.load(data)
    
    # puts "Got packet: #{packet}"
    
    case packet['t']
    when 'sawhash'
      hash = packet['h']
      unless @@known_infohashes[hash]
        puts "Got a new info hash: #{hash.unpack('H*')[0]}"
      
        search_hash(hash)
        
      else
        puts "Already know about #{hash.unpack('H*')[0]}"
      end
    when 'gotvalues'
      hash = packet['h']
      puts "Got search results for #{hash.unpack('H*')[0]}"
      
      unless @@known_infohashes[hash]
        if packet['values']
          ipv4s = packet['values']
          
          ipv4s.each do |rawaddress|
            addr = rawaddress.unpack("CCCCn")
            
            puts "  #{addr[3]}.#{addr[2]}.#{addr[1]}.#{addr[0]}:#{addr[4]}"
          end
        elsif packet['values6']
          
        end
        
        @@known_infohashes[hash] = true
      else
        puts "Already know about #{hash.unpack('H*')[0]}"
      end
    else
      puts "Unknown packet"
    end
  end
  
  def search_hash(hash)
    search = {'xyz' => 'search', 'info_hash' => hash}.bencode
    send_data(search)    
  end
end

EventMachine::run {
  EventMachine::open_datagram_socket "127.0.0.1", 5555, TorrentIndexer
  puts 'Torrent indexer listening on port 5555'
}
