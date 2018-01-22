###############################################################################
# OpenVAS Vulnerability Test
# $Id: sendmail_37543.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Sendmail NULL Character CA SSL Certificate Validation Security Bypass Vulnerability
#
# Authors:
# Michael Meyer
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

tag_summary = "Sendmail is prone to a security-bypass vulnerability because the
application fails to properly validate the domain name in a signed CA
certificate, allowing attackers to substitute malicious SSL
certificates for trusted ones.

Successfully exploiting this issue allows attackers to perform man-in-the-
middle attacks or impersonate trusted servers, which will aid in
further attacks.

Versions prior to Sendmail 8.14.4 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100415");
 script_version("$Revision: 8457 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
 script_cve_id("CVE-2009-4565");
 script_bugtraq_id(37543);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Sendmail NULL Character CA SSL Certificate Validation Security Bypass Vulnerability");


 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_category(ACT_GATHER_INFO);
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_sendmail_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37543");
 script_xref(name : "URL" , value : "http://www.sendmail.org/releases/8.14.4");
 script_xref(name : "URL" , value : "http://www.sendmail.org/");
 exit(0);
}


include("version_func.inc");

sendmailPort = get_kb_item("Services/smtp");

if(!sendmailPort){
  exit(0);
}

sendmailVer = get_kb_item("SMTP/" + sendmailPort + "/Sendmail");

if(sendmailVer != NULL)
{
  if(version_is_less(version:sendmailVer, test_version:"8.14.4")){
    security_message(sendmailPort);
    exit(0);
  }
}

exit(0);
