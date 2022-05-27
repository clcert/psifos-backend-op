class DLogTable(object):
    """
    Keeping track of discrete logs
    """

    def __init__(self, base, modulus):
        self.dlogs = {}
        self.dlogs[1] = 0
        self.last_dlog_result = 1
        self.counter = 0

        self.base = base
        self.modulus = modulus

    def increment(self):
        self.counter += 1

        # new value
        new_value = (self.last_dlog_result * self.base) % self.modulus

        # record the discrete log
        self.dlogs[new_value] = self.counter

        # record the last value
        self.last_dlog_result = new_value

    def precompute(self, up_to):
        while self.counter < up_to:
            self.increment()

    def lookup(self, value):
        return self.dlogs.get(value, None)