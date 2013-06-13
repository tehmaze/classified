# Parts are courtesey of `Ben Hogdson <http://benhodgson.com/>`_.

# Python imports
import logging
import re

# Project imports
from classified.probe.base import Probe


decimal_decoder = lambda s: int(s, 10)
decimal_encoder = lambda i: str(i)


def luhn_sum_mod_base(string, base=10, decoder=decimal_decoder):
    # Adapted from http://en.wikipedia.org/wiki/Luhn_algorithm
    digits = map(decoder, string)
    return (sum(digits[::-2]) +
        sum(map(lambda d: sum(divmod(2*d, base)), digits[-2::-2]))) % base


def generate(string, base=10, encoder=decimal_encoder,
    decoder=decimal_decoder):
    '''
    Calculates the Luhn mod N check character for the given input string. This
    character should be appended to the input string to produce a valid Luhn
    mod N string in the given base.

    >>> value = '4205092350249'
    >>> generate(value)
    '1'

    When operating in a base other than decimal, encoder and decoder callables
    should be supplied. The encoder should take a single argument, an integer,
    and return the character corresponding to that integer in the operating
    base. Conversely, the decoder should take a string containing a single
    character and return its integer value in the operating base. Note that
    the mapping between values and characters defined by the encoder and
    decoder should be one-to-one.

    For example, when working in hexadecimal:

    >>> hex_alphabet = '0123456789abcdef'
    >>> hex_encoder = lambda i: hex_alphabet[i]
    >>> hex_decoder = lambda s: hex_alphabet.index(s)
    >>> value = 'a8b56f'
    >>> generate(value, base=16, encoder=hex_encoder, decoder=hex_decoder)
    'b'
    >>> verify('a8b56fb', base=16, decoder=hex_decoder)
    True
    >>> verify('a8b56fc', base=16, decoder=hex_decoder)
    False
    '''

    d = luhn_sum_mod_base(string+encoder(0), base=base, decoder=decoder)
    if d != 0:
        d = base - d
    return encoder(d)


def verify(string, base=10, decoder=decimal_decoder):
    '''
    Verifies that the given string is a valid Luhn mod N string.

    >>> verify('5105105105105100') # MasterCard test number
    True

    When operating in a base other than decimal, encoder and decoder callables
    should be supplied. The encoder should take a single argument, an integer,
    and return the character corresponding to that integer in the operating
    base. Conversely, the decoder should take a string containing a single
    character and return its integer value in the operating base. Note that
    the mapping between values and characters defined by the encoder and
    decoder should be one-to-one.

    For example, 'b' is the correct check character for the hexadecimal string
    'a8b56f':

    >>> hex_decoder = lambda s: '0123456789abcdef'.index(s)
    >>> verify('a8b56fb', base=16, decoder=hex_decoder)
    True

    Any other check digit (in this example: 'c'), will result in a failed
    verification:

    >>> verify('a8b56fc', base=16, decoder=hex_decoder)
    False
    '''
    return luhn_sum_mod_base(string, base=base, decoder=decoder) == 0


def mask(card_number, keep=4):
    '''
    Mask a card number so it's suitable for printing.
    '''
    keep *= -1
    return '*' * len(card_number[:keep]) + card_number[keep:]


class PAN(Probe):
    '''
    Scan for Primary Account Number (PAN) data in (text) files.
    '''

    format = '{filename}[{line:d}]: {company} {card_number_masked}'
    ignore = '\x00-:\r\n'
    _check = {
        'American Express': dict(
            length = [15],
            prefix = re.compile(r'^3[47]'),
        ),
        'Diners Club EnRoute': dict(
            length = [15],
            prefix = re.compile(r'^(?:2014|2149)'),
        ),
        'Diners Club Carte Blanche': dict(
            length = [14],
            prefix = re.compile(r'^30[1-5]'),
        ),
        'Diners Club International': dict(
            length = [14],
            prefix = re.compile(r'^36'),
        ),
        'Diners Club America': dict(
            length = [14],
            prefix = re.compile(r'^5[45]'),
        ),
        'Discover': dict(
            length = [16],
            prefix = re.compile(r'^6011'),
        ),
        'InstaPayment': dict(
            length = [16],
            prefix = re.compile(r'^63[7-9]'),
        ),
        'JCB': dict(
            length = [16],
            prefix = re.compile(r'^(?:3088|3096|3112|3158|3337|352[89]|35[3-7][0-9]|358[0-9])'),
        ),
        'Laser': dict(
            length = range(12, 20),
            prefix = re.compile(r'^(?:6304|6706|6771|6709)'),
        ),
        'Maestro': dict(
            length = range(12, 20),
            prefix = re.compile(r'^(?:5018|5020|5038|5893|6304|6759|676[1-3]|0604)'),
        ),
        'MasterCard': dict(
            length = [16],
            prefix = re.compile(r'^5[1-5]'),
        ),
        'VISA': dict(
            length = [13, 16],
            prefix = re.compile(r'^4'),
        ),
    }

    def __init__(self, config, *args, **kwargs):
        super(PAN, self).__init__(config, *args, **kwargs)

        # Also keep track of per prefix size checks
        self._check_size = {}
        for company, checks in self._check.iteritems():
            for length in checks['length']:
                if length not in self._check_size:
                    self._check_size[length] = {}
                self._check_size[length][company] = checks['prefix']

        # Ignores, if configured
        if self.config.has_option('probe:pan', 'ignore'):
            self.ignore = map(
                lambda char: chr(int(char, 16)),
                self.config.getlist('probe:pan', 'ignore')
            )

    def luhn_check(self, card_number):
        # Do the Luhn check
        if verify(card_number):
            return self.process_prefix(card_number)

    def process_prefix(self, card_number):
        length = len(card_number)
        if length in self._check_size:
            for company, prefix in self._check_size[length].iteritems():
                if prefix.match(card_number):
                    return company

    def probe(self, item):
        # Keep track of consecutive ranges of numbers, stripping out potential
        # padding characters

        digits = []
        digits_min = min(self._check_size)
        digits_max = max(self._check_size)

        line = 0
        hits = 0
        try:
            limit = self.config.getint('probe:pan', 'limit')
        except self.config.NoOptionError:
            limit = 0

        prev = chr(0)
        for text in item.open():
            line += 1

            for char in text:
                # If we have a digit, append it to the digits list
                if char.isdigit():
                    digits.append(int(char))

                    if len(digits) >= digits_max:
                        digits = digits[1:]

                    if len(digits) >= digits_min:
                        for x in xrange(digits_min, digits_max + 1):
                            card_number = ''.join(map(str, digits[:x]))
                            card_company = self.luhn_check(card_number)
                            if card_company is not None:
                                self.record(item,
                                    raw=text,
                                    line=line,
                                    card_number=card_number,
                                    card_number_masked=mask(card_number),
                                    company=card_company,
                                )

                                # Rotate digits
                                digits = digits[x:]

                                # Keep track of hits
                                hits += 1
                                if limit and hits >= limit:
                                    logging.debug('pan probe hit limit '
                                                  'of %d' % limit)
                                    return
                                break

                # We ignore dashes, new lines and carriage returns
                elif char in self.ignore:
                    # .. if we have two successive ignored characters, reset
                    # the digits array
                    if prev in self.ignore:
                        digits = []

                # Otherwise we'll reset the buffer
                else:
                    digits = []

                # Keep track of the previous character
                prev = char
