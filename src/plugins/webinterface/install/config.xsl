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
  <p><span class="squares"><span>&#8250;&#8250;</span></span> <span class="news_title_grn">Configuration</span></p>
<table class="tab">

<!-- General Infos -->
<tr><th colspan="2">General Configuration</th></tr>
<tr><td>Ignor Autoconf</td><td><xsl:value-of select="config_ndpmon/settings/ignor_autoconf"/></td></tr>
<tr><td>Syslog Facility</td><td><xsl:value-of select="config_ndpmon/settings/syslog_facility"/></td></tr>
<tr><td>Administrator Mail Address</td><td><xsl:value-of select="config_ndpmon/settings/admin_mail"/></td></tr>
<tr><td>Reverse Lookups</td><td><xsl:value-of select="config_ndpmon/settings/use_reverse_hostlookups"/></td></tr>

<!-- Actions -->
<tr><th colspan="2">Low Priority Actions</th></tr>
<xsl:for-each select="config_ndpmon/settings/actions_low_priority">
<tr><td>Send Mail</td><td><xsl:value-of select="@sendmail"/></td></tr>
<tr><td>Syslog</td><td><xsl:value-of select="@syslog"/></td></tr>
<tr><td>Pipe Program</td><td><xsl:value-of select="@exec_pipe_program"/></td></tr>
</xsl:for-each>

<tr><th colspan="2">High Priority Actions</th></tr>
<xsl:for-each select="config_ndpmon/settings/actions_high_priority">
<tr><td>Send Mail</td><td><xsl:value-of select="@sendmail"/></td></tr>
<tr><td>Syslog</td><td><xsl:value-of select="@syslog"/></td></tr>
<tr><td>Pipe Program</td><td><xsl:value-of select="@exec_pipe_program"/></td></tr>
</xsl:for-each>

<!-- SOAP -->
<xsl:if test="config_ndpmon/settings/soap">
<tr><th colspan="2">SOAP Module</th></tr>
<xsl:for-each select="config_ndpmon/settings/soap">
<tr><td>Report URL</td><td><xsl:value-of select="@report_url"/></td></tr>
<tr><td>SSL enabled</td><td><xsl:value-of select="@ssl_enabled"/></td></tr>
<tr><td>SSL Certificate</td><td><xsl:value-of select="@ssl_certfile"/></td></tr>
<tr><td>SSL CA Certificate</td><td><xsl:value-of select="@ssl_cafile"/></td></tr>
<tr><td>SSL common name</td><td><xsl:value-of select="@ssl_commonname"/></td></tr>
</xsl:for-each>
</xsl:if>

<!-- Custom rules -->
<xsl:if test="config_ndpmon/rules">
	<tr><th colspan="2">Custom rules</th></tr>
	<xsl:for-each select="config_ndpmon/rules/rule">
		<tr><td>Rule</td><td><xsl:value-of select="@description"/></td></tr>
		<xsl:for-each select="match">
			<tr><td><i><xsl:value-of select="@field"/></i></td><td><i>Match <xsl:value-of select="@value"/></i></td></tr>
		</xsl:for-each>
		<xsl:for-each select="no-match">
			<tr><td><i><xsl:value-of select="@field"/></i></td><td><i>No-match <xsl:value-of select="@value"/></i></td></tr>
		</xsl:for-each>
	</xsl:for-each>
</xsl:if>

<!-- countermeasures -->
<xsl:if test="config_ndpmon/countermeasures">
<tr><th colspan="2">Countermeasures Politic</th></tr>
<tr><td>kill_illegitimate_router</td><td><xsl:value-of select="config_ndpmon/countermeasures/kill_illegitimate_router"/></td></tr>
<tr><td>kill_wrong_prefix</td><td><xsl:value-of select="config_ndpmon/countermeasures/kill_wrong_prefix"/></td></tr>
<tr><td>propagate_router_params</td><td><xsl:value-of select="config_ndpmon/countermeasures/propagate_router_params"/></td></tr>
<tr><td>propagate_router_dns</td><td><xsl:value-of select="config_ndpmon/countermeasures/propagate_router_dns"/></td></tr>
<tr><td>propagate_router_routes</td><td><xsl:value-of select="config_ndpmon/countermeasures/propagate_router_routes"/></td></tr>
<tr><td>propagate_neighbor_mac</td><td><xsl:value-of select="config_ndpmon/countermeasures/propagate_neighbor_mac"/></td></tr>
<tr><td>indicate_ndpmon_presence</td><td><xsl:value-of select="config_ndpmon/countermeasures/indicate_ndpmon_presence"/></td></tr>
</xsl:if>

<!-- Probes -->
<xsl:for-each select="config_ndpmon/probes/probe">
<br/><tr><th colspan="2">Probe</th></tr>
<tr><td>Name</td><td><xsl:value-of select="@name"/></td></tr>
<tr><td>Type</td><td><xsl:value-of select="@type"/></td></tr>
<xsl:if test="countermeasures_enabled">
<tr><td>Countermeasures enabled</td><td><xsl:value-of select="countermeasures_enabled"/></td></tr>
</xsl:if>
</xsl:for-each>

<!-- Routers -->
<xsl:for-each select="config_ndpmon/probes/probe/routers/router">
<tr><th colspan="2" align="left">Router</th></tr>
<tr><td>MAC Address</td><td><xsl:value-of select="mac"/></td></tr>
<tr><td>Link Local Address</td><td><xsl:value-of select="lla"/></td></tr>
<tr><td>Hop Limit</td><td><xsl:value-of select="param_curhoplimit"/></td></tr>
<tr><td>Reserved Flags</td><td><xsl:value-of select="param_flags_reserved"/></td></tr>
<tr><td>Router Lifetime</td><td><xsl:value-of select="param_router_lifetime"/></td></tr>
<tr><td>Reachable Timer</td><td><xsl:value-of select="param_reachable_timer"/></td></tr>
<tr><td>Retransmit Timer</td><td><xsl:value-of select="param_retrans_timer"/></td></tr>
<tr><td>MTU</td><td><xsl:value-of select="param_mtu"/></td></tr>
<tr><td>Volatile</td><td><xsl:value-of select="params_volatile"/></td></tr>
<tr><td colspan="2" ></td></tr>

<tr><td colspan="2" align="center" ><i><b>Prefixes Announced</b></i></td></tr>
<tr><td colspan="2" ></td></tr>
	<xsl:for-each select="prefixes/prefix">
	<tr><td>Prefix</td><td><xsl:value-of select="address"/>/<xsl:value-of select="mask"/></td></tr>
	<tr><td>Reserved Flags</td><td><xsl:value-of select="param_flags_reserved"/></td></tr>
	<tr><td>Valid Lifetime</td><td><xsl:value-of select="param_valid_time"/></td></tr>
	<tr><td>Preferred Lifetime</td><td><xsl:value-of select="param_preferred_time"/></td></tr>
	<tr><td colspan="2" ></td></tr>
	</xsl:for-each>


<xsl:if test="rdnss">
<tr><td colspan="2" align="center"><i><b>Recursive DNS Servers</b></i></td></tr>
	<xsl:for-each select="rdnss/nameserver">
	<tr><td>Nameserver</td><td><xsl:value-of select="text()"/> (<xsl:value-of select="@lifetime"/> s)</td></tr>
	</xsl:for-each>
<tr><td colspan="2" ></td></tr>
</xsl:if>

<xsl:if test="dnssl">
	<tr><td colspan="2" align="center" ><i><b>DNS Search List</b></i></td></tr>
	<xsl:for-each select="dnssl/domain">
	<tr><td>Domain</td><td><xsl:value-of select="text()"/> (<xsl:value-of select="@lifetime"/> s)</td></tr>
	</xsl:for-each>
<tr><td colspan="2" ></td></tr>
</xsl:if>

<xsl:if test="routes">
	<tr><td colspan="2" align="center" ><i><b>Routes Information</b></i></td></tr>
	<xsl:for-each select="routes/route">
	<tr><td colspan="2" ></td></tr>
	<tr><td>Prefix</td><td><xsl:value-of select="address"/>/<xsl:value-of select="mask"/></td></tr>
	<tr><td>Preference</td><td><xsl:value-of select="param_pref_reserved"/></td></tr>
	<tr><td>Lifetime</td><td><xsl:value-of select="lifetime"/></td></tr>
	</xsl:for-each>
<tr><td colspan="2" ></td></tr>
</xsl:if>


<tr><td>IPv6 Global Addresses</td><td>
	<xsl:for-each select="addresses/address">
	<xsl:value-of select="text()"/><br/>
	</xsl:for-each>
</td></tr>

<tr><td colspan="2" ></td></tr>
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

