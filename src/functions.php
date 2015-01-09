<?php

namespace IPv4;

/**
 * Address format constants
 */
const ADDRESS_FORMAT_BINARY     = 0x01;
const ADDRESS_FORMAT_BYTE_ARRAY = 0x02;
const ADDRESS_FORMAT_DOTDEC     = 0x04;
const ADDRESS_FORMAT_INSTANCE   = 0x08;
const ADDRESS_FORMAT_LONG       = 0x10;

/**
 * Convert a binary string to a byte array
 *
 * @param string $binary
 * @return int[]
 */
function binary_to_byte_array($binary)
{
    return long_to_byte_array(binary_to_long($binary));
}

/**
 * Convert a binary string to dotted-decimal notation
 *
 * @param string $binary
 * @return string
 */
function binary_to_dotted_decimal($binary)
{
    return implode('.', unpack('C*', $binary));
}

/**
 * Convert a binary string to a long integer
 *
 * @param string $binary
 * @return int
 */
function binary_to_long($binary)
{
    return current(unpack('N', $binary));
}

/**
 * Convert a binary string to an instance of Subnet
 *
 * @param string $binary
 * @param mixed $class
 * @return Subnet
 * @throws \InvalidArgumentException
 * @throws \LengthException
 * @throws \OutOfBoundsException
 */
function binary_to_subnet($binary, $class = null)
{
    if ($class === null) {
        return new Subnet(binary_to_long($binary));
    }

    if (is_object($class) && is_a($class, __NAMESPACE__ . '\\Subnet')) {
        $class = get_class($class);
    } else if (!is_subclass_of($class = (string)$class, __NAMESPACE__ . '\\Subnet')) {
        throw new \InvalidArgumentException('Supplied class does not inherit ' . __NAMESPACE__ . '\\Subnet');
    }

    return new $class(binary_to_long($binary));
}

/**
 * Convert a binary string to the specified $format
 *
 * @param string $binary
 * @param int $mode
 * @return string|int|int[]|Subnet
 * @throws \InvalidArgumentException
 * @throws \LengthException
 * @throws \OutOfBoundsException
 */
function binary_to_x($binary, $mode)
{
    if ($mode & ADDRESS_FORMAT_BINARY) {
        return $binary;
    } else if ($mode & ADDRESS_FORMAT_BYTE_ARRAY) {
        return binary_to_byte_array($binary);
    } else if ($mode & ADDRESS_FORMAT_DOTDEC) {
        return binary_to_dotted_decimal($binary);
    } else if ($mode & ADDRESS_FORMAT_LONG) {
        return binary_to_long($binary);
    }

    return binary_to_subnet($binary);
}

/**
 * Convert a byte array to a binary string
 *
 * @param int[] $bytes
 * @return string
 * @throws \LengthException
 * @throws \OutOfBoundsException
 */
function byte_array_to_binary(array $bytes)
{
    $bytes = validate_byte_array($bytes);
    return pack('C*', $bytes[0], $bytes[1], $bytes[2], $bytes[3]);
}

/**
 * Convert a byte array to a long integer
 *
 * @param int[] $bytes
 * @return string
 * @throws \LengthException
 * @throws \OutOfBoundsException
 */
function byte_array_to_dotted_decimal(array $bytes)
{
    return implode('.', validate_byte_array($bytes));
}

/**
 * Convert a byte array to a long integer
 *
 * @param int[] $bytes
 * @return int
 */
function byte_array_to_long(array $bytes)
{
    $bytes = validate_byte_array($bytes);
    return ($bytes[0] << 24) | ($bytes[1] << 16) | ($bytes[2] << 8) | $bytes[3];
}

/**
 * Convert a byte array to a long integer
 *
 * @param int[] $bytes
 * @param mixed $class
 * @return Subnet
 * @throws \InvalidArgumentException
 * @throws \LengthException
 * @throws \OutOfBoundsException
 */
function byte_array_to_subnet(array $bytes, $class = null)
{
    $bytes = validate_byte_array($bytes);

    if ($class === null) {
        return new Subnet($bytes);
    }

    if (is_object($class) && is_a($class, __NAMESPACE__ . '\\Subnet')) {
        $class = get_class($class);
    } else if (!is_subclass_of($class = (string)$class, __NAMESPACE__ . '\\Subnet')) {
        throw new \InvalidArgumentException('Supplied class does not inherit ' . __NAMESPACE__ . '\\Subnet');
    }

    return new $class($bytes);
}

/**
 * Convert a byte array to the specified $format
 *
 * @param int[] $bytes
 * @param int $format
 * @return string|int|int[]|Subnet
 * @throws \InvalidArgumentException
 * @throws \LengthException
 * @throws \OutOfBoundsException
 */
function byte_array_to_x(array $bytes, $format)
{
    if ($format & ADDRESS_FORMAT_BINARY) {
        return byte_array_to_binary($bytes);
    } else if ($format & ADDRESS_FORMAT_BYTE_ARRAY) {
        return validate_byte_array($bytes);
    } else if ($format & ADDRESS_FORMAT_DOTDEC) {
        return byte_array_to_dotted_decimal($bytes);
    } else if ($format & ADDRESS_FORMAT_LONG) {
        return byte_array_to_long($bytes);
    }

    return byte_array_to_subnet($bytes);
}

/**
 * Validate an normalize a byte array to exactly 4 integer elements 0 <= octet <= 255
 *
 * @param array $octets
 * @return int[]
 * @throws \LengthException
 * @throws \OutOfBoundsException
 */
function validate_byte_array(array $octets)
{
    if (count($octets) > 4) {
        throw new \LengthException('More than 4 octets');
    }

    $result = array();

    foreach (array_values($octets) + array(0, 0, 0, 0) as $i => $octet) {
        $result[] = $octet = (int)$octet;

        if ($octet < 0 || $octet > 255) {
            throw new \OutOfBoundsException('Octet ' . ($i + 1) . ' outside acceptable range 0 - 255');
        }
    }

    return $result;
}

/**
 * Convert a long integer to a binary string
 *
 * @param int $long
 * @return string
 */
function long_to_binary($long)
{
    return pack('N', (int)$long);
}

/**
 * Convert a long integer to a byte array
 *
 * @param int $long
 * @return int[]
 */
function long_to_byte_array($long)
{
    $long = (int)$long;

    return array(
        $long >> 24 & 0xFF,
        $long >> 16 & 0xFF,
        $long >> 8 & 0xFF,
        $long & 0xFF
    );
}

/**
 * Convert a long integer to a dotted-decimal string
 *
 * @param int $long
 * @return string
 */
function long_to_dotted_decimal($long)
{
    $long = (int)$long;
    return ($long >> 24 & 0xFF) . '.' . ($long >> 16 & 0xFF) . '.' . ($long >> 8 & 0xFF) . '.' . ($long & 0xFF);
}

/**
 * Convert a long integer to an instance of Subnet
 *
 * @param int $long
 * @param mixed $class
 * @return Subnet
 * @throws \InvalidArgumentException
 * @throws \LengthException
 * @throws \OutOfBoundsException
 */
function long_to_subnet($long, $class = null)
{
    if ($class === null) {
        return new Subnet((int)$long);
    }

    if (is_object($class) && is_a($class, __NAMESPACE__ . '\\Subnet')) {
        $class = get_class($class);
    } else if (!is_subclass_of($class = (string)$class, __NAMESPACE__ . '\\Subnet')) {
        throw new \InvalidArgumentException('Supplied class does not inherit ' . __NAMESPACE__ . '\\Subnet');
    }

    return new $class((int)$long);
}

/**
 * Convert a long integer to the specified $format
 *
 * @param int $long
 * @param int $format
 * @return string|int|int[]|Subnet
 * @throws \InvalidArgumentException
 * @throws \LengthException
 * @throws \OutOfBoundsException
 */
function long_to_x($long, $format)
{
    if ($format & ADDRESS_FORMAT_BINARY) {
        return long_to_binary($long);
    } else if ($format & ADDRESS_FORMAT_BYTE_ARRAY) {
        return long_to_byte_array($long);
    } else if ($format & ADDRESS_FORMAT_DOTDEC) {
        return long_to_dotted_decimal($long);
    } else if ($format & ADDRESS_FORMAT_LONG) {
        return $long;
    }

    return long_to_subnet($long);
}
