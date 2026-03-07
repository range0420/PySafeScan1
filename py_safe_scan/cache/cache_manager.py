"""缓存管理器 - 缓存LLM调用结果"""

import json
import hashlib
import pickle
import logging
from pathlib import Path
from typing import Any, Optional
import time

import config

logger = logging.getLogger(__name__)


class CacheManager:
    """缓存管理器，用于缓存LLM调用结果"""
    
    def __init__(self, cache_dir: Path = None, ttl: int = None):
        """
        初始化缓存管理器
        
        Args:
            cache_dir: 缓存目录
            ttl: 缓存生存时间（秒）
        """
        self.cache_dir = cache_dir or config.CACHE_DIR
        self.ttl = ttl or config.CACHE_TTL
        
        # 确保缓存目录存在
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # 内存缓存
        self.memory_cache = {}
        
        logger.info(f"缓存目录: {self.cache_dir}, TTL: {self.ttl}秒")
    
    def _get_cache_path(self, key: str) -> Path:
        """获取缓存文件路径"""
        # 使用哈希作为文件名
        hash_key = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{hash_key}.cache"
    
    def _is_expired(self, cache_path: Path) -> bool:
        """检查缓存是否过期"""
        if not cache_path.exists():
            return True
        
        mtime = cache_path.stat().st_mtime
        return (time.time() - mtime) > self.ttl
    
    def get(self, key: str) -> Optional[Any]:
        """
        从缓存获取数据
        
        Args:
            key: 缓存键
            
        Returns:
            缓存的数据，如果不存在或过期则返回None
        """
        # 先检查内存缓存
        if key in self.memory_cache:
            logger.debug(f"内存缓存命中: {key[:50]}...")
            return self.memory_cache[key]
        
        # 检查文件缓存
        cache_path = self._get_cache_path(key)
        
        if cache_path.exists() and not self._is_expired(cache_path):
            try:
                with open(cache_path, 'rb') as f:
                    data = pickle.load(f)
                
                # 存入内存缓存
                self.memory_cache[key] = data
                
                logger.debug(f"文件缓存命中: {cache_path.name}")
                return data
                
            except Exception as e:
                logger.error(f"读取缓存失败: {e}")
                return None
        
        logger.debug(f"缓存未命中: {key[:50]}...")
        return None
    
    def set(self, key: str, value: Any) -> bool:
        """
        设置缓存
        
        Args:
            key: 缓存键
            value: 要缓存的数据
            
        Returns:
            是否成功
        """
        # 存入内存缓存
        self.memory_cache[key] = value
        
        # 存入文件缓存
        cache_path = self._get_cache_path(key)
        
        try:
            with open(cache_path, 'wb') as f:
                pickle.dump(value, f)
            
            logger.debug(f"缓存已保存: {cache_path.name}")
            return True
            
        except Exception as e:
            logger.error(f"保存缓存失败: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """检查缓存是否存在且未过期"""
        # 检查内存缓存
        if key in self.memory_cache:
            return True
        
        # 检查文件缓存
        cache_path = self._get_cache_path(key)
        return cache_path.exists() and not self._is_expired(cache_path)
    
    def clear(self, key: Optional[str] = None):
        """
        清除缓存
        
        Args:
            key: 要清除的键，None表示清除所有
        """
        if key:
            # 清除指定键
            if key in self.memory_cache:
                del self.memory_cache[key]
            
            cache_path = self._get_cache_path(key)
            if cache_path.exists():
                cache_path.unlink()
                logger.info(f"缓存已清除: {cache_path.name}")
        else:
            # 清除所有
            self.memory_cache.clear()
            
            for cache_file in self.cache_dir.glob("*.cache"):
                cache_file.unlink()
            
            logger.info("所有缓存已清除")
    
    def cleanup_expired(self):
        """清理过期缓存"""
        expired_count = 0
        
        for cache_file in self.cache_dir.glob("*.cache"):
            if self._is_expired(cache_file):
                cache_file.unlink()
                expired_count += 1
        
        if expired_count > 0:
            logger.info(f"已清理 {expired_count} 个过期缓存文件")
    
    def get_stats(self) -> dict:
        """获取缓存统计信息"""
        cache_files = list(self.cache_dir.glob("*.cache"))
        
        total_size = 0
        for f in cache_files:
            total_size += f.stat().st_size
        
        return {
            "cache_dir": str(self.cache_dir),
            "file_count": len(cache_files),
            "total_size_bytes": total_size,
            "total_size_mb": total_size / (1024 * 1024),
            "memory_cache_entries": len(self.memory_cache),
            "ttl_seconds": self.ttl
        }
