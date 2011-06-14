require 'rubygems'
require 'eventmachine'
require 'bencode'
require 'em-redis'

$infohash_hosts = {}
$total_connections = 0

require './torrentgetter'

ConnectionLimit = 50

class TorrentIndexer < EventMachine::Connection
  def receive_data data
    packet = BEncode.load(data)
    
    # puts "Got packet: #{packet}"
    
    case packet['t']
    when 'sawhash'
      hash = packet['h']
        
      $redis.exists?(hash) do |response|
        unless response
          puts "Got unknown info hash, searching... #{hash.unpack('H*')[0]}"
          search_hash(hash)
        end
      end
    when 'gotvalues'
      hash = packet['h']
      
      $redis.exists?(hash) do |response|
        unless response
          $infohash_hosts[hash] = {}
          
          puts "Got search results for #{hash.unpack('H*')[0]}"

          if packet['values']
            ipv4s = packet['values']

            ipv4s.each do |rawaddress|
              addr = rawaddress.unpack("CCCCn")

              port = addr.pop
              address = addr.join('.')

              host = "#{address};#{port}"

              # puts "  IPv4: #{host}"

              $infohash_hosts[hash][host] ||= :unknown
            end
          elsif packet['values6']
            ipv6s = packet['values6']

            ipv6s.each do |rawaddress|
              addr = rawaddress.unpack("nnnnnnnnn")
              port = addr.pop

              address = addr.map{|value| value.to_s(16)}.join(":")

              host = "#{address};#{port}"
              # puts "  IPv6: #{host}"

              $infohash_hosts[hash][host] ||= :unknown
            end
          end
        end
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

EventMachine::run do 
  
  puts "Connecting to redis..."
  $redis = EM::Protocols::Redis.connect
  $redis.errback do |code|
    puts "Error code: #{code}"
  end
  
  EventMachine::open_datagram_socket "127.0.0.1", 5555, TorrentIndexer

  puts 'Torrent indexer listening on port 5555'
  
  EventMachine::PeriodicTimer.new(1) do
    puts "#{$total_connections} active metadata downloading connections"
    
    did_one = false
    
    if $total_connections < ConnectionLimit
      $infohash_hosts.each do |infohash, hosts|
        break if did_one
        
        hosts.each do |host, state|
          break if did_one
        
          if state == :unknown
            puts "Trying #{host}"
            addr, port = host.split(';')
            
            $redis.exists?(infohash) do |response|
              unless response
                EventMachine.connect(addr, port.to_i, TorrentGetter, infohash) do |getter|
                  getter.callback { |metadata|
                    puts "Downloaded metadata for #{infohash.unpack('H*')[0]}"
                    $infohash_hosts.delete(infohash)
                
                    $redis.set(infohash, metadata) do 
                      puts "Stored #{infohash.unpack('H*')[0]} (#{infohash.inspect}) to Redis"
                    end
                  }
              
                  getter.errback {
                    puts "Failed to download metadata"
                
                    if $infohash_hosts[infohash]
                      $infohash_hosts[infohash][host] = :failed
                  
                      $redis.exists?(hash) do |response|
                        if response
                          $infohash_hosts.delete(infohash)
                        end
                      end
                    end
                  }
                end
              else
                $infohash_hosts.delete(infohash)
              end
            end
            
            $infohash_hosts[infohash][host] = :trying
          
            did_one = true
            break
          end
        end
      end
    end
  end
end
