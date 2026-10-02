package io.aegis.security;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Prints this SDK's verdict for each corpus case, so the shared parity test can
 * compare Java against Node, Python and Go.
 */
public final class CorpusCheck {
  public static void main(String[] args) throws IOException {
    String raw = new String(System.in.readAllBytes(), StandardCharsets.UTF_8);
    List<String> cases = parseStringArray(raw);

    StringBuilder out = new StringBuilder("{");
    for (int i = 0; i < cases.size(); i++) {
      String input = cases.get(i);
      List<String> ids = new ArrayList<>();
      for (Aegis.Rule rule : Aegis.RULES) {
        if (rule.pattern().matcher(input).find()) {
          ids.add(rule.id());
        }
      }
      Collections.sort(ids);
      if (i > 0) {
        out.append(',');
      }
      out.append(Aegis.quote(input)).append(":[");
      for (int j = 0; j < ids.size(); j++) {
        if (j > 0) {
          out.append(',');
        }
        out.append(Aegis.quote(ids.get(j)));
      }
      out.append(']');
    }
    System.out.println(out.append('}'));
  }

  /** A minimal JSON string-array reader, so this tool needs no dependency. */
  static List<String> parseStringArray(String json) {
    List<String> values = new ArrayList<>();
    int i = json.indexOf('[');
    if (i < 0) {
      return values;
    }
    StringBuilder current = null;
    for (i = i + 1; i < json.length(); i++) {
      char c = json.charAt(i);
      if (current == null) {
        if (c == '"') {
          current = new StringBuilder();
        } else if (c == ']') {
          break;
        }
        continue;
      }
      if (c == '\\') {
        char next = json.charAt(++i);
        switch (next) {
          case 'n' -> current.append('\n');
          case 'r' -> current.append('\r');
          case 't' -> current.append('\t');
          case 'u' -> {
            current.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16));
            i += 4;
          }
          default -> current.append(next);
        }
      } else if (c == '"') {
        values.add(current.toString());
        current = null;
      } else {
        current.append(c);
      }
    }
    return values;
  }

  private CorpusCheck() {}
}
