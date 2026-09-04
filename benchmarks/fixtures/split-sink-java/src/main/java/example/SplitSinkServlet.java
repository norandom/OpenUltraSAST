package example;

import jakarta.servlet.http.HttpServletRequest;
import java.sql.Connection;

class SplitSinkServlet {
  void search(HttpServletRequest request, Connection connection) throws Exception {
    String term = request.getParameter("q");
    String sql = String.format("select * from items where title like '%%%s%%'", term);
    connection.createStatement().executeQuery(sql); // CWE-89 split-sink: sql built on prior line (regex blind spot)
  }
}
