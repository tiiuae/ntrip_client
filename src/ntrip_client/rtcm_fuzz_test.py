try:
    import atheris
except ImportError:
    raise ImportError("You need to install atheris to run this script.")
import sys

with atheris.instrument_imports():
    from rtcm_parser import RTCMParser


def TestOneInput(data):
    parser = RTCMParser()
    parser.parse(data)


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
