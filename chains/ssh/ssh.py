import importlib
import re

s = "SSH-2.0-OpenSSH_7.0p2 Debian-7+deb13u1"


def regreSSHion(ip: str, port: int = 22) -> None:
    return f"regreSSHion on {ip}:{port}......"

def loginEnum(ip: str, port: int = 22) -> None:
    return f"Enumeration users on {ip}:{port}...."

def bruteSSH(ip: str, port: int | None = 22, dist: str | None = None):
    if dist is not None:
        import optional

        vars = optional.default_login_passwords.keys()
        return f"Brute {dist} on {ip}:{port}......."
    else:
        return f"Brute on {ip}:{port}......."

KNOWN_VULNERABILITIES = {
    "regreSSHion": {
        "version": {"min": "8.5p1", "max": "9.7p1"},
        "handler": regreSSHion
    },
    "loginEnum": {
        "version": {"min": "2.3", "max": "7.1"},
        "handler": loginEnum
    },
    "brute": {
        "version": {"min": "0.0", "max": "999.9"},
        "handler": bruteSSH
    }
}





def parse_ssh_version(version_str: str) -> tuple:
    """
    Парсит строку версии SSH (как полную, так и короткую) в кортеж чисел.
    Примеры:
      'SSH-2.0-OpenSSH_9.6p1' -> (9, 6, 1)
      '8.5p1' -> (8, 5, 1)
      '7.1' -> (7, 1, 0)
    """

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


def known_vulnerabilities(version: str) -> list:
    res = []

    # Парсим проверяемую версию один раз
    current_version = parse_ssh_version(version)

    for cve_name, bounds in KNOWN_VULNERABILITIES.items():
        min_version = parse_ssh_version(bounds["version"]["min"])
        max_version = parse_ssh_version(bounds["version"]["max"])

        # Проверяем, входит ли текущая версия в диапазон [min; max] включительно
        if min_version <= current_version <= max_version:
            res.append(cve_name)

    return res

def server_os(version_str: str) -> str | None:
    import optional

    vars = optional.default_login_passwords.keys()

    version_str = version_str.lower()
    for var in vars:
        if var.lower() in version_str:
            return var

    return None


if __name__ == "__main__":
    print(known_vulnerabilities(s.split(" ")[0]))