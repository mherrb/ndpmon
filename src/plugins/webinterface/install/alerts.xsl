<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<!-- match all the document -->
<xsl:template match="/">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<meta name="description" content="#" />
<meta name="keywords" content="#" />
<meta name="author" content="#" />
<link rel="stylesheet" type="text/css" href="doctors_office.css" media="screen" />
<title>NDPMon - Neighbor Discovery Protocol MONitor</title>
</head>
<body>
<div id="banner">
  <div class="top_links clearfix" id="topnav">
    <ul>
      <li><a href="http://ndpmon.sf.net">Official Website</a></li>
	 <li><a href="https://sourceforge.net/projects/ndpmon/">SourceForge Project Page</a></li>
    </ul>
  </div>
  <img alt="pumpkin" src="img/header_logo.gif" />
  <div class="page_title"><span id="page_title">NDPMon - IPv6 Neighbor Discovery Protocol MONitor</span></div>
</div>
<div class="leftcontent" id="nav"> <img alt="bg image" src="img/left_bg_top.gif" />
  <ul>
    <li><a href="./index.html">About</a></li>
    <li><a href="./config_ndpmon.xml">Configuration</a></li>
    <li><a href="./alerts.html">Alerts and Reports</a></li>
    <li><a href="./neighbors.html">Neighbors</a></li>
  </ul>
</div>

<div id="centercontent">
	<p><span class="squares"><span>&#8250;&#8250;</span></span> <span class="news_title_grn">Alerts and Reports</span></p>
<table class="alert">
<tr>
<th width="150">Time</th>
<th>Probe</th>
<th>Reason</th>
<th>Ethernet Address 1</th>
<th>Ethernet Address 2</th>
<th>IPv6 Address</th>
</tr>

<!-- Requires XSL-FO formater fop
<xsl:template match="alerts">
	<fo:block font-size="10pt" >
		<xsl:apply-templates/>
	</fo:block>
</xsl:template>
-->

<!-- Alerts -->
<xsl:for-each select="alerts/alert">
<!-- The newest at the first place -->
<xsl:sort select="time" order="descending"/>

<xsl:choose>
  <!-- High Priority is red -->
  <xsl:when test="priority=2">
    <tr bgcolor="red">
    <td><xsl:value-of select="time_str"/></td>
    <td><xsl:value-of select="probe"/></td>
    <td><xsl:value-of select="reason"/></td>
    <td><xsl:value-of select="ethernet_address1"/></td>
    <td><xsl:value-of select="ethernet_address2"/></td>
    <td><xsl:value-of select="ipv6_address"/></td>
    </tr>  
  </xsl:when>

  <!-- New is green -->
  <xsl:when test="(reason='new IP') or (reason='new station') or (reason='new lla')">
    <tr bgcolor="#33FF33">
    <td><xsl:value-of select="time_str"/></td>
    <td><xsl:value-of select="probe"/></td>
    <td><xsl:value-of select="reason"/></td>
    <td><xsl:value-of select="ethernet_address1"/></td>
    <td><xsl:value-of select="ethernet_address2"/></td>
    <td><xsl:value-of select="ipv6_address"/></td>
    </tr>
  </xsl:when>

  <!-- default -->
  <xsl:otherwise>
    <tr bgcolor="orange">
    <td><xsl:value-of select="time_str"/></td>
    <td><xsl:value-of select="probe"/></td>
    <td><xsl:value-of select="reason"/></td>
    <td><xsl:value-of select="ethernet_address1"/></td>
    <td><xsl:value-of select="ethernet_address2"/></td>
    <td><xsl:value-of select="ipv6_address"/></td>
    </tr>  
  </xsl:otherwise>
</xsl:choose>

</xsl:for-each>

</table>

<div class="footer" id="footer">
Copyright 2012 (- <a href="http://madynes.loria.fr">MADYNES Project</a> -) - Design by <a href="#">pogy366</a> 
</div>

</div>
</body>
</html>
</xsl:template>
</xsl:stylesheet>

