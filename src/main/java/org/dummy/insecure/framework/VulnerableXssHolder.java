/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.dummy.insecure.framework;

import lombok.extern.slf4j.Slf4j;

@Slf4j
// TODO move back to lesson
public class VulnerableXssHolder {

  private String userInput;
  private String userName;
  private String comment;
  private String searchQuery;

  public VulnerableXssHolder(String userInput) {
    super();
    this.userInput = userInput;
  }

  public VulnerableXssHolder(String userName, String comment) {
    super();
    this.userName = userName;
    this.comment = comment;
  }

  public VulnerableXssHolder(String userName, String comment, String searchQuery) {
    super();
    this.userName = userName;
    this.comment = comment;
    this.searchQuery = searchQuery;
  }

  /**
   * Returns user input without any sanitization or escaping.
   * This method is vulnerable to XSS attacks as it directly returns
   * user-controlled content that may contain malicious scripts.
   */
  public String getUnsafeUserInput() {
    log.info("Returning unsafe user input: {}", userInput);
    return userInput;
  }

  /**
   * Returns HTML content with user input directly embedded.
   * This demonstrates stored XSS vulnerability.
   */
  public String getUnsafeHtmlContent() {
    String html = "<div class='user-content'>" + userName + "</div>";
    html += "<p class='comment'>" + comment + "</p>";
    log.info("Generating unsafe HTML content");
    return html;
  }

  /**
   * Returns JavaScript code with user input directly concatenated.
   * This demonstrates reflected XSS vulnerability in JavaScript context.
   */
  public String getUnsafeJavaScript() {
    String js = "var searchTerm = '" + searchQuery + "';";
    js += "document.getElementById('result').innerHTML = 'You searched for: ' + searchTerm;";
    log.info("Generating unsafe JavaScript with user input");
    return js;
  }

  /**
   * Returns user input wrapped in HTML attributes without escaping.
   * This demonstrates XSS in HTML attribute context.
   */
  public String getUnsafeHtmlAttribute() {
    String html = "<input type='text' value='" + userInput + "' />";
    log.info("Generating unsafe HTML attribute");
    return html;
  }

  /**
   * Returns user input in a URL without proper encoding.
   * This demonstrates XSS in URL context.
   */
  public String getUnsafeUrl() {
    String url = "https://example.com/search?q=" + searchQuery;
    log.info("Generating unsafe URL");
    return url;
  }

  /**
   * Returns user input directly in a script tag.
   * This is a classic XSS vulnerability pattern.
   */
  public String getUnsafeScriptTag() {
    String html = "<script>var data = " + userInput + ";</script>";
    log.info("Generating unsafe script tag");
    return html;
  }

  @Override
  public String toString() {
    return "VulnerableXssHolder [userInput="
        + userInput
        + ", userName="
        + userName
        + ", comment="
        + comment
        + ", searchQuery="
        + searchQuery
        + "]";
  }

  // Getters and setters
  public String getUserInput() {
    return userInput;
  }

  public void setUserInput(String userInput) {
    this.userInput = userInput;
  }

  public String getUserName() {
    return userName;
  }

  public void setUserName(String userName) {
    this.userName = userName;
  }

  public String getComment() {
    return comment;
  }

  public void setComment(String comment) {
    this.comment = comment;
  }

  public String getSearchQuery() {
    return searchQuery;
  }

  public void setSearchQuery(String searchQuery) {
    this.searchQuery = searchQuery;
  }
}
