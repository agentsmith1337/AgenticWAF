import redis
import time
import uuid

class RedisIPTrie:
    def __init__(self, redis_client):
        self.r = redis_client
        self.ROOT = "trie:root"

        # Ensure root exists
        self.r.hsetnx(self.ROOT, "_init", "1")

    # ---------- Internal Helpers ----------

    def _new_node(self):
        return f"trie:{uuid.uuid4()}"

    def _split_ip(self, ip):
        return ip.split(".")

    # ---------- Public API ----------

    def block_ip(self, ip, timestamp=None):
        """
        Add IP to trie with timestamp
        """
        if timestamp is None:
            timestamp = int(time.time())

        node = self.ROOT
        octets = self._split_ip(ip)

        for octet in octets:
            child = self.r.hget(node, octet)
            if not child:
                child = self._new_node()
                self.r.hset(node, octet, child)
            node = child

        self.r.hset(node, "_end", "1")

        # Store timestamp
        self.r.hset("blocked:timestamps", ip, timestamp)

        # Store expiry
        self.r.zadd("blocked:expiry", {ip: timestamp})

    def is_blocked(self, ip):
        """
        Lookup IP in trie
        """
        node = self.ROOT
        octets = self._split_ip(ip)

        for octet in octets:
            node = self.r.hget(node, octet)
            if not node:
                return False

        return self.r.hexists(node, "_end")

    def unblock_ip(self, ip):
        """
        Remove IP from trie + indexes
        """
        path = []
        node = self.ROOT
        octets = self._split_ip(ip)

        for octet in octets:
            path.append((node, octet))
            node = self.r.hget(node, octet)
            if not node:
                return

        self.r.hdel(node, "_end")
        self.r.hdel("blocked:timestamps", ip)
        self.r.zrem("blocked:expiry", ip)

        # Optional cleanup of empty nodes (safe)
        for parent, octet in reversed(path):
            child = self.r.hget(parent, octet)
            if self.r.hlen(child) == 0:
                self.r.hdel(parent, octet)
                self.r.delete(child)
            else:
                break

    def cleanup_expired(self, max_age_seconds=86400):
        """
        Remove IPs older than max_age_seconds
        """
        cutoff = int(time.time()) - max_age_seconds

        expired_ips = self.r.zrangebyscore(
            "blocked:expiry",
            0,
            cutoff
        )

        for ip in expired_ips:
            self.unblock_ip(ip.decode())

        return len(expired_ips)
    
    def clear_trie(self):
        for key in self.r.scan_iter("trie:*"):
            self.r.delete(key)

