from setuptools import setup, find_packages

with open("requirements.txt") as f:
	install_requires = f.read().strip().split("\n")

# get version from __version__ variable in icici_integration_server/__init__.py
from icici_integration_server import __version__ as version

setup(
	name="icici_integration_server",
	version=version,
	description="Manages ICICI Integrations",
	author="Aerele Technologies Pvt Ltd.",
	author_email="hello@aerele.in",
	packages=find_packages(),
	zip_safe=False,
	include_package_data=True,
	install_requires=install_requires
)
