<?php

namespace IPv4;

class Subnet implements \ArrayAccess, \Iterator
{
    /**
     * Constants to control whether getHosts() returns the network/broadcast addresses
     */
    const HOSTS_WITH_NETWORK   = 0x100;
    const HOSTS_WITH_BROADCAST = 0x200;
    const HOSTS_ALL            = 0x400;

    /**
     * Base address as a binary string
     *
     * @var string
     */
    protected $address;

    /**
     * Mask as a binary string
     *
     * @var string
     */
    protected $mask;

    /**
     * Counter to track the current iteration offset
     *
     * @var int
     */
    private $iteratorOffset = 0;

    /**
     * Parse an address specification to a byte array
     *
     * @param string|int|int[] $address
     * @return array
     * @throws \InvalidArgumentException
     * @throws \LengthException
     * @throws \OutOfBoundsException
     */
    private function parseAddressToArray($address)
    {
        $mask = null;

        if ($address === null || (is_string($address) && trim($address) === '')) {
            $address = $mask = array(0, 0, 0, 0);
        } else if (is_int($address)) {
            $address = $this->longToByteArray($address);
        } else if (is_string($address)) {
            $parts = preg_split('#\s*/\s*#', trim($address), -1, PREG_SPLIT_NO_EMPTY);

            if (count($parts) > 2) {
                throw new \InvalidArgumentException('No usable IP address supplied: syntax error');
            } else if ($parts[0] === '') {
                throw new \InvalidArgumentException('No usable IP address supplied: IP address empty');
            }

            $address = preg_split('#\s*\.\s*#', $parts[0], -1, PREG_SPLIT_NO_EMPTY);
            $mask = !empty($parts[1]) ? $parts[1] : null;
        } else if (is_array($address)) {
            $address = array_values($address);
        } else {
            throw new \InvalidArgumentException('No usable IP address supplied: must be a string, integer or byte array');
        }

        if (count($address) > 4) {
            throw new \LengthException('No usable IP address supplied: address has more than 4 octets');
        }
        $address = $this->validateOctetArray($address, 'No usable IP address supplied');

        return array($address, $mask);
    }

    /**
     * Parse a mask specification to a byte array
     *
     * @param string|int|int[] $mask
     * @param int[] $address
     * @return array|int[]
     * @throws \InvalidArgumentException
     * @throws \LengthException
     * @throws \OutOfBoundsException
     */
    private function parseMaskToArray($mask, array $address)
    {
        if ($mask === null) {
            $mask = array_pad(array(), count($address), 255);
        } else if (is_int($mask)) {
            $mask = $this->longToByteArray($mask);
        } else if (is_string($mask)) {
            $mask = preg_split('#\s*\.\s*#', trim($mask), -1, PREG_SPLIT_NO_EMPTY);

            switch (count($mask)) {
                case 1: // CIDR
                    $cidr = (int) $mask[0];
                    if ($cidr === 0) {
                        // Shifting 32 bits on a 32 bit system doesn't work, so treat this as a special case
                        $mask = array(0, 0, 0, 0);
                    } else if ($cidr <= 32) {
                        // This looks odd, but it's the nicest way I have found to get the 32 least significant bits set in a
                        // way that always works on both 32 and 64 bit platforms
                        $base = ~((~0 << 16) << 16);
                        $mask = $this->longToByteArray($base << (32 - $cidr));
                    } else {
                        throw new \InvalidArgumentException('Supplied mask invalid: CIDR outside acceptable range 0 - 32');
                    }
                    break;

                case 4:
                    break; // Dotted decimal

                default:
                    throw new \InvalidArgumentException('Supplied mask invalid: Must be either a full dotted-decimal or a CIDR');
            }
        } else if (is_array($mask)) {
            $mask = array_values($mask);
        } else {
            throw new \InvalidArgumentException('Supplied mask invalid: Type invalid');
        }

        $mask = $this->validateOctetArray($mask, 'Supplied mask invalid');

        // Check bits are contiguous from left
        $asciiBits = sprintf('%032b', $this->byteArrayToLong($mask));
        if (strpos(rtrim($asciiBits, '0'), '0') !== false) {
            throw new \InvalidArgumentException('Supplied mask invalid: Set bits are not contiguous from the most significant bit');
        }

        return $mask;
    }

    /**
     * Normalise a byte array to 4 elements 0 <= val <= 255
     *
     * @param int[] $octets
     * @param string $errPrefix
     * @return int[]|false
     * @throws \LengthException
     * @throws \OutOfBoundsException
     */
    private function validateOctetArray($octets, $errPrefix)
    {
        if (count($octets) > 4) {
            throw new \LengthException($errPrefix . ': More than 4 octets');
        }

        $result = array();

        foreach (array_values($octets) + array(0, 0, 0, 0) as $i => $octet) {
            $result[] = $octet = (int)$octet;

            if ($octet < 0 || $octet > 255) {
                throw new \OutOfBoundsException($errPrefix . ': octet ' . ($i + 1) . ' outside acceptable range 0 - 255');
            }
        }

        return $result;
    }

    /**
     * Ensure an arbitrary value is an instance of this class
     *
     * @param string|int|int[]|static $subject
     * @return static
     * @throws \InvalidArgumentException
     * @throws \LengthException
     * @throws \OutOfBoundsException
     */
    protected function normalizeComparisonSubject($subject)
    {
        if (!is_object($subject)) {
            return new static($subject);
        } else if (!($subject instanceof self)) {
            throw new \InvalidArgumentException('Comparison subject must be an instance of ' . __CLASS__);
        }

        return $subject;
    }

    /**
     * Constructor
     *
     * The $address argument specifies the base address of the subnet. It may be specified as a string in dotted-decimal
     * notation, an integer (only the least significant 32 bits will be considered) or an array of integers, treated as
     * a byte array. Partial addresses will be right-padded to 4 octets with zeroes. When specified as a string the
     * mask may also be specified in the first argument, separated from the address with a forward slash, in either
     * dotted-decimal or CIDR notation. If no address or NULL is passed, 0.0.0.0/0 is assumed.
     * The following example strings are all valid:
     *   192.168                    (192.168.0.0/16)
     *   192.168.0.1                (192.168.0.1/32)
     *   192.168.0.0/24             (192.168.0.0/24)
     *   192.168.0.0/255.255.255.0  (192.168.0.0/24)
     *
     * The mask can also be specified in the $mask argument. If a mask is also specified as part of the address, the
     * value from $mask takes precedence. The $mask argument may be specified as a string, an integer (only the least
     * significant 32 bits will be considered) or an array of integers, treated as a byte array. If a string is
     * specified and contains only a single integer <= 32, it will be treated as a CIDR mask - therefore, the string
     * values '255.255.255.0' and '24' are equivalent. A dotted-decimal notation mask must specify all 4 octets. If no
     * $mask is passed when an address was specified, the mask will be constructed with 255 for each supplied address
     * octet, and right-padded to 4 octets with zeroes.
     *
     * @param string|int|int[] $address
     * @param string|int|int[] $mask
     * @throws \InvalidArgumentException
     * @throws \LengthException
     * @throws \OutOfBoundsException
     */
    public function __construct($address = null, $mask = null)
    {
        list($address, $addressMask) = $this->parseAddressToArray($address);
        $mask = $this->parseMaskToArray($mask === null && $addressMask !== null ? $addressMask : $mask, $address);

        $this->mask = $this->byteArrayToBinary($mask);
        $this->address = $this->byteArrayToBinary($address) & $this->mask;
    }

    /**
     * Get dotted-decimal or CIDR notation, depending on whether this subnet contains more than one address
     *
     * @return string
     */
    public function __toString()
    {
        if ($this->getHostsCount() === 1) {
            $result = $this->toDottedDecimal();
        } else {
            $result = $this->toCIDR();
        }
        return $result;
    }

    /**
     * Override the default debug handler in 5.6+ to show human-readable values for $address and $mask
     *
     * @return string[]
     */
    public function __debugInfo()
    {
        return [
            'address' => $this->binaryToDottedDecimal($this->address),
            'mask' => $this->binaryToDottedDecimal($this->mask),
        ];
    }

    /**
     * Determine whether an array key exists
     *
     * @param int|string $offset
     * @return bool
     */
    public function offsetExists($offset)
    {
        if ($offset === 'network' || $offset === 'broadcast') {
            return true;
        }

        $offset = filter_var($offset, FILTER_VALIDATE_INT);
        if ($offset === false || $offset < 0) {
            return false;
        }

        return $offset < $this->getHostsCount();
    }

    /**
     * Fetch the host address referenced by an array key
     *
     * @param int|string $offset
     * @return static|null
     */
    public function offsetGet($offset)
    {
        if (!$this->offsetExists($offset)) {
            return null;
        }

        if ($offset === 'network') {
            $address = $this->getNetworkAddress(self::ADDRESS_LONG);
        } else if ($offset === 'broadcast') {
            $address = $this->getBroadcastAddress(self::ADDRESS_LONG);
        } else {
            // How much the address needs to be adjusted by to account for network address
            $adjustment = (int) ($this->getHostsCount() > 2);
            $address = $this->binaryToLong($this->address) + $offset + $adjustment;
        }

        return $this->longToInstance($address);
    }

    /**
     * No-op, subnets are immutable
     *
     * @param int|string $offset
     * @param mixed $value
     */
    public function offsetSet($offset, $value) {}

    /**
     * No-op, subnets are immutable
     *
     * @param int|string $offset
     */
    public function offsetUnset($offset) {}

    /**
     * Get the host address referenced by the iteration pointer
     *
     * @return static|null
     */
    public function current()
    {
        return $this->offsetGet($this->iteratorOffset);
    }

    /**
     * Get the iteration pointer
     *
     * @return int
     */
    public function key()
    {
        return $this->iteratorOffset;
    }

    /**
     * Advance the iteration pointer
     */
    public function next()
    {
        $this->iteratorOffset++;
    }

    /**
     * Reset the iteration pointer to the beginning
     */
    public function rewind()
    {
        $this->iteratorOffset = 0;
    }

    /**
     * Determine whether the iteration pointer references a valid host address
     *
     * @return bool
     */
    public function valid()
    {
        return $this->iteratorOffset < $this->getHostsCount();
    }

    /**
     * Get all host addresses in this subnet as an array in the format indicated by $mode, where $mode is one of the
     * ADDRESS_* constants. The HOSTS_* constants may also be used with this method to specify whether the network
     * and broadcast addresses are included.
     *
     * @param int $mode
     * @return string[]|int[]|static[]
     */
    public function getHosts($mode = self::ADDRESS_INSTANCE)
    {
        // Parse flags and initialise vars
        $bin = (bool) ($mode & self::ADDRESS_BINARY);
        $int = (bool) ($mode & self::ADDRESS_LONG);
        $dd = (bool) ($mode & self::ADDRESS_DOTDEC);
        $base = $this->binaryToLong($this->address);
        $mask = $this->binaryToLong($this->mask);
        $hasNwBc = !($mask & 0x03);
        $result = array();

        // Get network address if requested
        if (($mode & self::HOSTS_WITH_NETWORK) && $hasNwBc) {
            $result[] = $base;
        }

        // Get hosts
        for ($current = $hasNwBc ? $base + 1 : $base; ($current & $mask) === $base; $current++) {
            $result[] = $current;
        }

        // Remove broadcast address if present and not requested
        if ($hasNwBc && !($mode & self::HOSTS_WITH_BROADCAST)) {
            array_pop($result);
        }

        // Convert to the correct type
        if ($bin) {
            $result = array_map(array($this, 'longToBinary'), $result);
        } else if ($dd) {
            $result = array_map(array($this, 'longToDottedDecimal'), $result);
        } else if (!$int) {
            $result = array_map(array($this, 'longToInstance'), $result);
        }

        return $result;
    }

    /**
     * Get the number of hosts in the subnet, excluding the network and broadcast addresses
     *
     * @return mixed|string
     */
    public function getHostsCount()
    {
        $count = $this->getBroadcastAddress(self::ADDRESS_LONG) - $this->getNetworkAddress(self::ADDRESS_LONG);
        return $count > 2 ? $count - 1 : $count + 1; // Adjust return value to exclude network/broadcast addresses
    }

    /**
     * Get the network address in the format indicated by $mode, where $mode is one of the ADDRESS_* constants.
     *
     * @param int $mode
     * @return string|int|int[]|static
     */
    public function getNetworkAddress($mode = self::ADDRESS_INSTANCE)
    {
        return $this->binaryToX($this->address, $mode);
    }

    /**
     * Get the broadcast address in the format indicated by $mode, where $mode is one of the ADDRESS_* constants.
     *
     * @param int $mode
     * @return string|int|int[]|static
     */
    public function getBroadcastAddress($mode = self::ADDRESS_INSTANCE)
    {
        return $this->binaryToX($this->address | ~$this->mask, $mode);
    }

    /**
     * Get the mask of this subnet
     *
     * @param int $mode
     * @return string|int|int[]|static
     */
    public function getMask($mode = self::ADDRESS_DOTDEC)
    {
        return $this->binaryToX($this->mask, $mode);
    }

    /**
     * Get network address of this subnet in dotted-decimal form
     *
     * @return string
     */
    public function toDottedDecimal()
    {
        $result = $this->getNetworkAddress(self::ADDRESS_DOTDEC);
        if ($this->mask !== "\xFF\xFF\xFF\xFF") {
            $result .= '/'.$this->getMask(self::ADDRESS_DOTDEC);
        }
        return $result;
    }

    /**
     * Get this subnet in CIDR notation
     *
     * @return string
     */
    public function toCIDR()
    {
        $address = $this->getNetworkAddress(self::ADDRESS_DOTDEC);
        $cidr = strlen(trim(sprintf('%b', $this->getMask(self::ADDRESS_LONG)), '0'));
        return $address.'/'.$cidr;
    }

    /**
     * Determine whether this subnet contains another subnet
     *
     * @param string|int|int[]|static $subject
     * @return bool
     * @throws \InvalidArgumentException
     * @throws \LengthException
     * @throws \OutOfBoundsException
     */
    public function contains($subject)
    {
        $subject = $this->normalizeComparisonSubject($subject);

        $subjectAddress = $subject->getNetworkAddress(self::ADDRESS_BINARY);
        $subjectMask = $subject->getMask(self::ADDRESS_BINARY);

        return $this->mask !== $subjectMask                                 // masks are not equal
            && ($this->mask | ($this->mask ^ $subjectMask)) !== $this->mask // subject mask narrower
            && ($subjectAddress & $this->mask) === $this->address;          // base addresses are equal
    }

    /**
     * Determine whether this subnet is within another subnet
     *
     * @param string|int|int[]|static $subject
     * @return bool
     * @throws \InvalidArgumentException
     * @throws \LengthException
     * @throws \OutOfBoundsException
     */
    public function within($subject)
    {
        return $this->normalizeComparisonSubject($subject)->contains($this);
    }

    /**
     * Determine whether another subnet is equal to this one
     *
     * @param string|int|int[]|static $subject
     * @return bool
     * @throws \InvalidArgumentException
     * @throws \LengthException
     * @throws \OutOfBoundsException
     */
    public function equalTo($subject)
    {
        $subject = $this->normalizeComparisonSubject($subject);

        return $this->address === $subject->getNetworkAddress(self::ADDRESS_BINARY) && $this->mask === $subject->getMask(self::ADDRESS_BINARY);
    }

    /**
     * Determine whether another subnet intersects with this one
     *
     * @param string|int|int[]|static $subject
     * @return bool
     * @throws \InvalidArgumentException
     * @throws \LengthException
     * @throws \OutOfBoundsException
     */
    public function intersect($subject)
    {
        $subject = $this->normalizeComparisonSubject($subject);

        return $this->equalTo($subject) || $this->contains($subject) || $subject->contains($this);
    }
}
