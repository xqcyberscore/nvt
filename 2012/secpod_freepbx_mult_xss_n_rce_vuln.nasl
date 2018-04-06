###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_freepbx_mult_xss_n_rce_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# FreePBX Multiple Cross Site Scripting and Remote Command Execution Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation may allow remote attackers to steal cookie-based
  authentication credentials or execute arbitrary commands within the context
  of the affected application.
  Impact Level: System/Application";
tag_affected = "FreePBX versions 2.9.0 and 2.10.0";
tag_insight = "Multiple flaws are caused by an,
  - Improper validation of user-supplied input by multiple scripts, which
    allows attacker to execute arbitrary HTML and script code on the user's
    browser session in the security context of an affected site.
  - Input passed to the 'callmenum' parameter in recordings/misc/callme_page.php
    (when 'action' is set to 'c') is not properly verified before being used.
    This can be exploited to inject and execute arbitrary shell commands.";
tag_solution = "Apply the patch from below link,
  http://www.freepbx.org/trac/ticket/5711";
tag_summary = "This host is running FreePBX and is prone to multiple cross site
  scripting and remote command execution vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902823");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(52630);
  script_cve_id("CVE-2012-4869", "CVE-2012-4870");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-27 16:35:51 +0530 (Tue, 27 Mar 2012)");
  script_name("FreePBX Multiple Cross Site Scripting and Remote Command Execution Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48475");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48463");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74173");
  script_xref(name : "URL" , value : "http://www.freepbx.org/trac/ticket/5711");
  script_xref(name : "URL" , value : "http://www.freepbx.org/trac/ticket/5713");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18649");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/111130/freepbx2100-exec.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_freepbx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("freepbx/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Variable Initialization
dir = "";
url = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Directory
if(!dir = get_dir_from_kb(port:port, app:"freepbx")){
  exit(0);
}

## Construct Attack Request
urls = make_list(
      "/recordings/index.php?login='><script>alert(document.cookie)</script>",
      '/panel/index_amp.php?context="<script>alert(document.cookie)</script>');

foreach url (urls)
{
  ## Try XSS attack and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url: dir+url, check_header:TRUE,
     pattern:"<script>alert\(document.cookie\)</script>"))
  {
    security_message(port);
    exit(0);
  }
}
