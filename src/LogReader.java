import java.io.*;
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
    private HashMap<String, Integer> map = new HashMap<>();
    private String log;
    private boolean reachedFailedLogins;
    private boolean reachedIllegalUsers;
    private PrintStream output;

    private static final String HOST_NAME_PATTERN = "\\(([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}\\)\\:";
    private static final String IP_PATTERN = "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}";
    private static final String FAIL_COUNT_PATTERN = "\\d*\\stimes|\\d*\\stime";

    private LogReader(int limit) {
        this.securityLimit = limit;
    }

    public static void main(String[] args) {
        LogReader reader = new LogReader(5);
        reader.setupStandardOutput();
        reader.setPrams();

        String test = "127.0.0.1:";
        String[] a = test.split(":");

        try {
            reader.getLogAsString();
            reader.readFile();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void setPrams() {
        reachedIllegalUsers = false;
        reachedFailedLogins = false;
    }

    private void readFile() throws IOException {
        readFailedLogins();

        System.out.println("\n" + "MAP:");
        for(Map.Entry<String, Integer> entry : map.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
    }

    private void getLogAsString() throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        StringBuilder builder = new StringBuilder();

        String line;
        while((line = br.readLine()) != null) {
            builder.append(line);
            builder.append("\n");
        }
        log = builder.toString();
        //System.out.println("File as string: \n" + builder.toString());
    }

    private void setupStandardOutput() {
        try {
            output = new PrintStream(new FileOutputStream("black_list.txt"));
        }
        catch (FileNotFoundException e) {
            //TODO throw exception or something
            System.out.println("File not fond");
        }
        System.setOut(output);
    }

    private void checkOrder(String line) {
        if(line.equals("Failed logins from:")) {
            reachedFailedLogins = true;
            if(reachedIllegalUsers) {
                //TODO throw an exception
                System.out.println("Illegal users before failed logins!");
            }
        }
        else if(line.equals("Illegal users from:")) {
            System.out.println("Illegal users set True");
            reachedFailedLogins = true;
        }
    }

    private void checkFormat() {
        if(!reachedIllegalUsers && blanks > 1) {
            //TODO throw an exception
        }
    }

    private void readFailedLogins() throws IOException {
        InputStream is = new ByteArrayInputStream(log.getBytes());
        BufferedReader br = new BufferedReader(new InputStreamReader(is));

        String line;
        boolean startRead = false;
        blanks = 0;
        while ((line = br.readLine()) != null) {
            checkOrder(line);
            if(line.equals("Failed logins from:")) {
                startRead = true;
            }
            else if(startRead && readNextLine(line)) {
                checkFormat();
                String[] portions = line.trim().split(" ");
                isValidLine(portions, portions.length);
            }
        }
        br.close();
    }

    private boolean readNextLine(String line) throws IOException {
        if(line.isEmpty()) {
            blanks++;
            checkFormat();
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
