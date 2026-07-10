"""
IP-Reality / qian 自定义异常层级
"""

class QianError(Exception):
    """所有 qian 异常的基类"""


class ConnectionError(QianError):
    """TCP 连接失败 / 超时"""


class TLSHandshakeError(QianError):
    """TLS 握手失败"""


class CertParseError(QianError):
    """证书解析失败"""


class CFVerifyError(QianError):
    """Cloudflare 响应头验证失败"""


class ConfigError(QianError):
    """配置参数错误"""
