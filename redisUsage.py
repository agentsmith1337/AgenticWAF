import redis 
import time 
import uuid 
from redis_ip_trie import RedisIPTrie
r = redis.Redis(host="localhost", port=6379, decode_responses=False)
trie = RedisIPTrie(r)

# trie.block_ip("192.168.1.10")
# print(trie.is_blocked("192.168.1.10"))  # True
# trie.block_ip("192.168.1.11")
# trie.clear_trie()
# print(trie.is_blocked("192.168.1.11"))
# time.sleep(1)
removed = trie.cleanup_expired(max_age_seconds=0)
print("Removed:", removed)

print(trie.is_blocked("127.0.0.1"))  # False
