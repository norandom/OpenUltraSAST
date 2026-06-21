package example;

import jakarta.servlet.http.HttpServletRequest;
import java.sql.Connection;

class VulnerableServlet {
  void ping(HttpServletRequest request) throws Exception {
    Runtime.getRuntime().exec("ping -c 1 " + request.getParameter("host"));
  }

  void lookup(HttpServletRequest request, Connection connection) throws Exception {
    String sql = "select * from users where name = '" + request.getParameter("name") + "'";
    connection.createStatement().executeQuery(sql);
  }
}
