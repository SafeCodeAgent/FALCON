from pathlib import Path


def vendor_path(name: str) -> Path:
    package = Path(__file__).resolve().parent
    source_checkout = package.parent / "vendor" / name
    if source_checkout.exists():
        return source_checkout
    installed = package / "vendor" / name
    if installed.exists():
        return installed
    raise FileNotFoundError(f"vendored {name} component was not packaged")
