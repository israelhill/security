package project10;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogReader {
    private int securityLimit = 3;
    private int blanks;
    private HashMap<User, Integer> map = new HashMap<>();
    private String log;
    private boolean reachedIllegalUsers;
    private ArrayList<String> blackList = new ArrayList<>();

    private static final String HOST_NAME_PATTERN = "\\(([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}\\)\\:";
    private static final String IP_PATTERN = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
    private static final String FAIL_COUNT_PATTERN = "\\d*\\stimes|\\d*\\stime";

    public LogReader(int securityLimit) {
        this.securityLimit = securityLimit;
    }

    public static void main(String[] args) {
        int threshold;
        // if there is a number format exception, default to the value three
        try {
            threshold = Integer.valueOf(args[0]);
        }
        catch (NumberFormatException e) {
            threshold = 3;
            System.out.println("Invalid arg, setting threshold to 3.");
        }
        LogReader logReader = new LogReader(threshold);
        setupStandardOutput();
        logReader.setPrams();

        try {
            logReader.getLogAsString();
            logReader.readFile();
        }
        catch (IOException e) {
            throw new InvalidFileException(e);
        }
        logReader.writeBlackListToFile();
    }

    /**
     * redirect standard output to a file called black_list.txt
     */
    private static void setupStandardOutput() {
        PrintStream output = null;
        try {
            output = new PrintStream(new FileOutputStream("black_list.txt"));
        }
        catch (FileNotFoundException e) {
            System.out.println("Input file not Found. Please place file in correct directory.");
        }
        System.setOut(output);
    }

    private void setPrams() {
        reachedIllegalUsers = false;
    }

    /**
     * read the file into a string
     * @throws IOException
     */
    private void getLogAsString() throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        StringBuilder builder = new StringBuilder();

        String line;
        while((line = br.readLine()) != null) {
            builder.append(line);
            builder.append("\n");
        }
        log = builder.toString();
    }

    /**
     * create the black list by iterating over the hash map and checking user fail counts against the allowed limit
     */
    private void createBlackList() {
        assert (!map.isEmpty());
        for(Map.Entry<User, Integer> entry : map.entrySet()) {
            if (entry.getValue() > securityLimit) {
                if(entry.getKey().hasHostName()) {
                    blackList.add(entry.getKey().getHostName());
                }
                else {
                    blackList.add(entry.getKey().getIp());
                }
            }
        }
    }

    /**
     * create the black list and write it to standard output
     */
    private void writeBlackListToFile() {
        createBlackList();
        String host;
        final String FIVE_BLANKS = "     ";
        StringBuilder builder = new StringBuilder();
        final int MAX_LINE_LENGTH = 79;

        for(int i = 0; i < blackList.size(); i++) {
            host = blackList.get(i) + ",";
            if((builder.length() + host.length()) < MAX_LINE_LENGTH) {
                builder.append(host);
            }
            else {
                builder.append("\\");
                System.out.println(FIVE_BLANKS + builder.toString());
                builder = new StringBuilder();
                builder.append(host);
            }
        }

        if(builder.length() > 0) {
            // One host left in builder. Remove the comma and print it without a back slash
            String lastLine = builder.toString().substring(0, builder.length() - 1);
            System.out.println(FIVE_BLANKS + lastLine);
        }
    }

    /**
     * start reading the security log
     * @throws IOException
     */
    private void readFile() throws IOException {
        try {
            readSecurityLog();
        } catch (InvalidSyntaxException e) {
            throw new InvalidFileException(e);
        }
    }

    /**
     * REad the security log and make sure each line is correct
     * @throws IOException
     * @throws InvalidSyntaxException
     */
    private void readSecurityLog() throws IOException, InvalidSyntaxException {
        InputStream is = new ByteArrayInputStream(log.getBytes());
        BufferedReader br = new BufferedReader(new InputStreamReader(is));

        String line;
        boolean startRead = false;
        blanks = 0;
        int lineNum = 0;
        while ((line = br.readLine()) != null) {
            lineNum++;
            checkOrder(line);
            checkFormat();
            if(line.equals("Failed logins from:")) {
                startRead = true;
            }
            else if(startRead && readNextLine(line)) {
                assert (!line.isEmpty());
                assert (blanks < 2);
                checkFormat();
                String[] portions = line.trim().split(" ");
                isValidLine(portions, portions.length, lineNum);
            }
        }
        br.close();
    }

    /**
     * check if it is okay to read a given line
     * @param line
     * @return
     * @throws IOException
     * @throws InvalidSyntaxException
     */
    private boolean readNextLine(String line) throws IOException, InvalidSyntaxException {
        if(line.isEmpty()) {
            blanks++;
            checkFormat();
        }

        return (blanks < 2) && !line.isEmpty() && !line.equals("Illegal users from:");
    }

    /**
     * cehck if a line is valid based on the number of args allowed to be on a line
     * @param portions
     * @param size
     */
    private void isValidLine(String[] portions, int size, int lineNum) {
        String ip;
        String host;
        String count;
        assert (lineNum > 0);
        
        switch(size) {
            case 3: {
                String[] split1 = portions[0].split(":");
                ip = split1[0];
                count = portions[1] + " " + portions[2];
                try {
                    assert (portions.length > 0);
                    validateTwoArgLine(ip, count);
                }
                catch (InvalidSyntaxException e) {
                    throw new InvalidFileException(e);
                }
                break;
            }
            case 4: {
                ip = portions[0];
                host = portions[1];
                count = portions[2] + " " + portions[3];
                try {
                    validateThreeArgLine(ip, host, count);
                } catch (InvalidSyntaxException e) {
                    throw new InvalidFileException(e);
                }
                break;
            }
            default: {
                String message = "Check number of args on line " + String.valueOf(lineNum);
                throw new InvalidFileException("Problem reading line: " + message);
            }
        }
    }

    /**
     * insert users into a map along with their fail counts
     * @param key
     * @param value
     */
    private void insertIntoMap(User key, Integer value) {
        if(!map.containsKey(key)) {
            map.put(key, value);
        }
        else {
            int oldValue = map.get(key);
            int newValue = oldValue + value;
            map.put(key, newValue);
        }
    }

    /**
     * return a formatted count string
     * @param count
     * @return
     */
    private String getCount(String count) {
        String[] split = count.split(" ");
        return split[0];
    }

    /**
     * return a formatted domain name
     * @param host
     * @return
     */
    private String getCleanHostName(String host) {
        return host.substring(1, host.length() - 2);
    }

    //BARRICADE METHODS

    /**
     * make sure that a line containing 3 args is valid
     * @param ip
     * @param host
     * @param count
     * @throws InvalidSyntaxException
     */
    public void validateThreeArgLine(String ip, String host, String count) throws InvalidSyntaxException {
        boolean validHost = isValidPattern(HOST_NAME_PATTERN, host);
        boolean validIp = isValidPattern(IP_PATTERN, ip);
        boolean validCount = isValidPattern(FAIL_COUNT_PATTERN, count);

        if(validHost && validIp && validCount) {
            User user = new User(ip, getCleanHostName(host));
            Integer fails = Integer.valueOf(getCount(count));
            insertIntoMap(user, fails);
        }
        else {
            String syntax = ip + " " + host + " " + count;
            throw new InvalidSyntaxException(syntax);
        }
    }

    /**
     * make sure that a line containing 2 args is valid
     * @param ip
     * @param count
     * @throws InvalidSyntaxException
     */
    public void validateTwoArgLine(String ip, String count) throws InvalidSyntaxException {
        boolean validIp = isValidPattern(IP_PATTERN, ip);
        boolean validCount = isValidPattern(FAIL_COUNT_PATTERN, count);

        if(validIp && validCount) {
            User user = new User(ip, null);
            Integer fails = Integer.valueOf(getCount(count));
            insertIntoMap(user, fails);
        }
        else {
            String syntax = ip + " " + count;
            throw new InvalidSyntaxException(syntax);
        }
    }

    /**
     * check that the Failed Logins section comes before the illegal users section
     * @param line
     * @throws InvalidSyntaxException
     */
    public void checkOrder(String line) throws InvalidSyntaxException {
        if(line.equals("Failed logins from:")) {
            if(reachedIllegalUsers) {
                throw new InvalidSyntaxException("Illegal user section is before Failed logins");
            }
        }
        else if(line.equals("Illegal users from:")) {
            reachedIllegalUsers = true;
        }
    }

    /**
     * check that there are not too many blanks before we reach the illegal users section
     * @throws InvalidSyntaxException
     */
    public void checkFormat() throws InvalidSyntaxException {
        if(!reachedIllegalUsers && blanks > 1) {
            throw new InvalidSyntaxException("Too many blank lines in file.");
        }
    }

    /**
     * user regex pattern matching to validate ip addresses, domain names, and fail counts
     * @param regexPattern
     * @param s
     * @return
     */
    public boolean isValidPattern(String regexPattern, String s) {
        Pattern pattern = Pattern.compile(regexPattern);
        Matcher matcher = pattern.matcher(s);
        return matcher.matches();
    }
}
