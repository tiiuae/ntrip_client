try:
    import atheris
except ImportError:
    raise ImportError("You need to install atheris to run this script.")
import sys

with atheris.instrument_imports():
    from nmea_parser import NMEAParser


def TestOneInput(data):
    parser = NMEAParser()
    parser.is_valid_sentence(data)


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
