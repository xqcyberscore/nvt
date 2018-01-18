###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mailenable_43182.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# MailEnable  'MESMTRPC.exe' SMTP Service Multiple Remote Denial of Service Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "According to its banner, the remote MailEnable is prone to multiple
remote denial-of-service vulnerabilities.

An attacker can exploit these issue to crash the affected application,
denying service to legitimate users.

MailEnable 4.25 Standard Edition, Professional Edition, and Enterprise
Edition are vulnerable; other versions may also be affected.";

tag_solution = "The vendor has released hotfix ME-10044. Please see the references for
more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100798");
 script_version("$Revision: 8447 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-09-14 15:16:41 +0200 (Tue, 14 Sep 2010)");
 script_bugtraq_id(43182);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-2580");

 script_name("MailEnable  'MESMTRPC.exe' SMTP Service Multiple Remote Denial of Service Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43182");
 script_xref(name : "URL" , value : "http://www.mailenable.com/");
 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-112/");
 script_xref(name : "URL" , value : "http://www.mailenable.com/hotfix/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/513648");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("version_func.inc");
include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

if(get_kb_item('SMTP/'+port+'/broken'))exit(0);
if(!get_port_state(port))exit(0);

banner = get_smtp_banner(port:port);
if(!banner || "MailEnable" >!< banner)exit(0);

version = eregmatch(pattern:"Version: ([0-9.]+)",string:banner);
if(isnull(version[1]))exit(0);

if(version_is_less(version:version[1],test_version: "4.26")) {
  security_message(port:port);
  exit(0);
}  

exit(0);

  
