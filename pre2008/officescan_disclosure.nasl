# OpenVAS Vulnerability Test
# $Id: officescan_disclosure.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: OfficeScan configuration file disclosure
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "Trend Micro OfficeScan Corporate Edition (Japanese version: Virus 
Buster Corporate Edition) web-based management console let anybody 
access /officescan/hotdownload without authentication.

Reading the configuration file /officescan/hotdownload/ofcscan.ini
will reveal information on your system. More, it contains passwords
that are encrypted by a weak specific algorithm; so they might be 
decrypted";

tag_solution = "upgrade OfficeScan";

# References:
# Date:  Tue, 16 Oct 2001 11:34:56 +0900
# From: "snsadv@lac.co.jp" <snsadv@lac.co.jp>
# To: bugtraq@securityfocus.com
# Subject: [SNS Advisory No.44] Trend Micro OfficeScan Corporate Edition
# (Virus Buster Corporate Edition) Configuration File Disclosure Vulnerability 

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11074");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2001-1151");
 script_bugtraq_id(3438);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 
 name = "OfficeScan configuration file disclosure";
 script_name(name);
 


 
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
 script_require_ports("Services/www", 80);
 script_dependencies("http_version.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
res = is_cgi_installed_ka(port:port, item:"/officescan/hotdownload/ofscan.ini");
if(res)
{
 res = is_cgi_installed_ka(port:port, item:"/officescan/hotdownload/openvas.ini");
 if ( res ) exit(0);
 security_message(port);
}
