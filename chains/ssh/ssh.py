import importlib
import re


def parse_ssh_version(version_str: str) -> tuple:
    if 'OpenSSH' in version_str:
        version_str = version_str.split("_")[-1]

    # Ищет паттерн версии в любом месте строки
    match = re.search(r'(?:OpenSSH_)?(\d+)\.(\d+)(?:p(\d+))?', version_str)
    if not match:
        raise ValueError(f"Не удалось распознать формат версии OpenSSH: {version_str}")

    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) else 0

    return (major, minor, patch)

def server_os(version_str: str) -> str | None:
    import optional

    vars = optional.default_login_passwords.keys()

    version_str = version_str.lower()
    for var in vars:
        if var.lower() in version_str:
            return var

    return None