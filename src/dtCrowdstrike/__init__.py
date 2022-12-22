from ._version import _VERSION, _AUTHOR_EMAIL, _AUTHOR, _TITLE
from ._version import _MAINTAINER, _DESCRIPTION, _DOCS_URL, _PROJECT_URL

__version__ = _VERSION
__maintainer__ = _MAINTAINER
__author__ = _AUTHOR
__author_email__ = _AUTHOR_EMAIL
__description__ = _DESCRIPTION
__title__ = _TITLE
__project_url__ = _PROJECT_URL
__docs_url__ = _DOCS_URL


def version():
    return __version__


def title():
    return __title__
