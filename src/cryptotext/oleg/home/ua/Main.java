package cryptotext.oleg.home.ua;

import java.io.*;
import java.util.Scanner;

import cryptotext.oleg.home.ua.*;

public class Main {

  static String getPassword(InputStream in) throws IOException {
    //Obtaining a reference to the console.
    Console con = System.console();

    // Checking If there is no console available, then exit.
    if (con == null) {
      BufferedReader reader = new BufferedReader(new InputStreamReader(in));
      return  reader.readLine();
    }
//
    //to read password and then display it
    System.out.println("Enter the password: ");
    char[] ch = con.readPassword();
    //Password save char type

    //converting char array into string
    String pass = String.valueOf(ch);
    //System.out.println("Password is: " + pass);
    return pass;
  }

  static enum Mode {
    ENCRYPT,
    DECRYPT
  }

  ;

  static void handleInput(Mode mode, InputStream in, String pass, OutputStream out) throws Exception {
    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));

    StringBuilder src = new StringBuilder();
    String line;
    while ((line = reader.readLine()) != null) {
      src.append(line);
      if(mode == Mode.ENCRYPT)
        src.append('\n');
    }

    if (mode == Mode.ENCRYPT) {
      String res = OpenSslAes.encrypt(pass, src.toString());
      //System.out.println("Result is: " + res);
      writer.write(res);
    } else {
      String res = OpenSslAes.decrypt(pass, src.toString());
      //System.out.println("Result is: " + res);
      writer.write(res);
    }
    writer.flush();

  }

  public static void main(String[] args) {
    OutputStream out = System.out;
    InputStream in = System.in;
    Mode mode = Mode.DECRYPT;
    String pass = null;

    for (int i = 0; i < args.length; i++) {
      String arg = args[i];

      if (arg.equals("-e") || arg.equals("--encrypt")) {
        mode = Mode.ENCRYPT;
        continue;
      }

      if (arg.equals("-d") || arg.equals("--decrypt")) {
        mode = Mode.DECRYPT;
        continue;
      }

      if ((arg.equals("-i") || arg.equals("--input")) && i < args.length - 1) {
        try {
          in = new FileInputStream(args[++i]);
        } catch (FileNotFoundException e) {
          e.printStackTrace();
        }
        continue;
      }

      if ((arg.equals("-o") || arg.equals("--output")) && i < args.length - 1) {
        try {
          out = new FileOutputStream(args[++i]);
        } catch (FileNotFoundException e) {
          e.printStackTrace();
        }
      }

      if ((arg.equals("-p") || arg.equals("--password")) && i < args.length - 1) {
        pass = args[++i];
        continue;
      }

    }

    if (pass == null) {
      try {
        pass = getPassword(in);
      } catch (IOException e) {
        e.printStackTrace();
      }
    }

    try {
      handleInput(mode, in, pass, out);
    }

    catch (Exception e) {
      e.printStackTrace();
    }
  }
}
