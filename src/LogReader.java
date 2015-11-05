import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.IntSummaryStatistics;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogReader {
    private int securityLimit;
    private Pattern pattern;
    private Matcher matcher;
    private int blanks;
    private boolean reachedIllegalUsers = false;
    private HashMap<String, Integer> map = new HashMap<>();

    private static final String HOST_NAME_PATTERN = "\\(([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}\\)\\:";
    private static final String IP_PATTERN = "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}";
    private static final String FAIL_COUNT_PATTERN = "\\d*\\stimes|\\d*\\stime";

    private LogReader(int limit) {
        this.securityLimit = limit;
    }

    public static void main(String[] args) {
        LogReader reader = new LogReader(5);

        String test = "127.0.0.1:";
        String[] a = test.split(":");

        try {
            File dir = new File(".");
            File securityLog = new File(dir.getCanonicalPath() + File.separator + "file.txt");
            reader.readFile(securityLog);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void readFile(File file) throws IOException {
        readFailedLogins(file);

        System.out.println("\n" + "MAP:");
        for(Map.Entry<String, Integer> entry : map.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
    }

    private void readFailedLogins(File file) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(file));

        String line;
        boolean startRead = false;
        blanks = 0;
        while ((line = br.readLine()) != null) {
            if(line.equals("Failed logins from:")) {
                startRead = true;
            }
            else if(startRead && readNextLine(line)) {
                System.out.print(blanks);
                String[] portions = line.trim().split(" ");
                isValidLine(portions, portions.length);
            }
        }
        br.close();
    }

    private boolean readNextLine(String line) throws IOException {
        if(line.isEmpty()) {
            blanks++;
        }

        return (blanks < 2) && !line.isEmpty();
    }

    private void isValidLine(String[] portions, int size) {
        switch(size) {
            case 3: {
                String[] split1 = portions[0].split(":");
                String ip = split1[0];
                if(isValidIP(ip) && isValidCount(portions[1] + " " + portions[2])) {
                    Integer value = Integer.valueOf(portions[1]);
                    insertIntoMap(ip, value);
                }
                break;
            }
            case 4: {
                if(isValidIP(portions[0]) && isValidHostName(portions[1]) && isValidCount(portions[2] + " " + portions[3])) {
                    String ip = portions[0];
                    Integer value = Integer.valueOf(portions[2]);
                    insertIntoMap(ip, value);
                }
                break;
            }
            default: {
                //TODO throw an Exception
                // too many or too few args
                System.out.println("Something is wrong:" + " " + portions[0]);
            }
        }
    }

    private void insertIntoMap(String key, Integer value) {
        if(!map.containsKey(key)) {
            map.put(key, value);
        }
        else {
            int oldValue = map.get(key);
            int newValue = oldValue + value;
            map.put(key, newValue);
        }
    }

    private boolean isValidIP(String ipAddress) {
        pattern = Pattern.compile(IP_PATTERN);
        matcher = pattern.matcher(ipAddress);
        return matcher.matches();
    }

    private boolean isValidCount(String count) {
        pattern = Pattern.compile(FAIL_COUNT_PATTERN);
        matcher = pattern.matcher(count);
        return matcher.matches();
    }

    private boolean isValidHostName(String host) {
        pattern = Pattern.compile(HOST_NAME_PATTERN);
        matcher = pattern.matcher(host);
        return matcher.matches();
    }
}
