"""
IP-Reality / xiao 自定义异常层级
"""

class XiaoError(Exception):
    """所有 xiao 异常的基类"""


class ConnectionError(XiaoError):
    """TCP 连接失败 / 超时"""


class TLSHandshakeError(XiaoError):
    """TLS 握手失败"""


class CertParseError(XiaoError):
    """证书解析失败"""


class CFVerifyError(XiaoError):
    """Cloudflare 响应头验证失败"""


class ConfigError(XiaoError):
    """配置参数错误"""
