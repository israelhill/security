package project10;

import org.junit.Test;

import static org.junit.Assert.*;
import project10.LogReader;

public class LogReaderTest {

    private static final String HOST_NAME_PATTERN = "\\(([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}\\)\\:";
    private static final String IP_PATTERN = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
    private static final String FAIL_COUNT_PATTERN = "\\d*\\stimes|\\d*\\stime";
    private LogReader logReader = new LogReader(5);

    @Test
    public void testValidIp() throws Exception {
        String[] ips = {"192.168.23.4", "0.0.0.0", "8.8.8.8", "0.1.12.123", "123.123.123.123"};
        for(String s : ips) {
            assertTrue(logReader.isValidPattern(IP_PATTERN, s));
        }
    }

    @Test
    public void testInvalidIP() throws Exception {
        String[] ips = {"1", "05", ".9", "..45", "hello", "23,565.65.88", "8,256.9.8", "400.400.400.400"};
        for(String s : ips) {
            assertFalse(logReader.isValidPattern(IP_PATTERN, s));
        }
    }

    @Test
    public void testValidDomain() {
        String[] domains = {"(ip-50-62-42-229.ip.secureserver.net):", "(ip-50-63-56-230.ip.secureserver.net):"};
        for(String s: domains) {
            assertTrue(logReader.isValidPattern(HOST_NAME_PATTERN, s));
        }
    }

    @Test
    public void testInvalidDomain() {
        String[] domains = {"(ip-50-62-42-229.ip.secureserver,net):", "(ip-50-63-56-230.ip.secur**eserver.net):"};
        for(String s: domains) {
            assertFalse(logReader.isValidPattern(HOST_NAME_PATTERN, s));
        }
    }

    @Test
    public void testValidCount() {
        String[] counts = {"3 times", "45 times", "1 time"};
        for(String s: counts) {
            assertTrue(logReader.isValidPattern(FAIL_COUNT_PATTERN, s));
        }
    }

    @Test
    public void testInvalidCount() {
        String[] counts = {"3 tims", "4 tis", "1 ime", "122", "hello", ""};
        for(String s: counts) {
            assertFalse(logReader.isValidPattern(FAIL_COUNT_PATTERN, s));
        }
    }
}