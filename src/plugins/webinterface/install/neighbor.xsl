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
  <p><span class="squares"><span>&#8250;&#8250;</span></span> <span class="news_title_grn">Neighbors</span></p>


<xsl:for-each select="neighbors/probe">
<table class="tab">

<tr><th>Probe Name</th><th>MAC Address</th><th colspan="2">IPv6 Global Addresses</th></tr>
<tr>
<td><xsl:value-of select="@name"/></td>
<td><xsl:value-of select="@mac"/></td>
<td  colspan="2" text-align="center">
	<xsl:for-each select="address">
	<xsl:value-of select="text()"/><br/>
	</xsl:for-each>
</td>
</tr>

<tr><th>Time</th><th>MAC Address (Vendor)</th><th>Link Local Address</th><th>IPv6 Global Addresses</th></tr>

<!-- Neighbors -->
<xsl:for-each select="neighbor">
<tr>
<td><xsl:value-of select="lastseen/@lastseenstr"/></td>
<td><xsl:value-of select="mac"/> (<xsl:value-of select="mac/@vendor"/>)</td>
<td><xsl:value-of select="lla"/></td>
<td>
	<xsl:for-each select="addresses/address">
	<xsl:variable name="first" select="@firstseenstr"/>
	<xsl:variable name="last" select="@lastseenstr"/>
	<xsl:value-of select="text()"/> (<xsl:value-of select="$first"/>;<xsl:value-of select="$last"/>)<br/>
	</xsl:for-each>
</td></tr>
</xsl:for-each>

</table>
</xsl:for-each>


<div class="footer" id="footer">
Copyright 2012 (- <a href="http://madynes.loria.fr">MADYNES Project</a> -) - Design by <a href="#">pogy366</a> 
</div>

</div>
</body>
</html>
</xsl:template>
</xsl:stylesheet>

