###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_im_manager_44299.nasl 8495 2018-01-23 07:57:49Z teissa $
#
# Symantec IM Manager Multiple SQL Injection Vulnerabilities
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

tag_summary = "Symantec IM Manager is prone to multiple SQL-injection vulnerabilities
because it fails to sufficiently sanitize user-supplied data before
using it in an SQL query.

A successful exploit can allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

Symantec IM Manager versions 8.4.15 and prior are vulnerable.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100876");
 script_version("$Revision: 8495 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-10-28 13:41:07 +0200 (Thu, 28 Oct 2010)");
 script_bugtraq_id(44299);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0112");

 script_name("Symantec IM Manager Multiple SQL Injection Vulnerabilities");


 script_tag(name:"qod_type", value:"registry");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_symantec_prdts_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Symantec/IM/Manager");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44299");
 script_xref(name : "URL" , value : "http://www.symantec.com");
 script_xref(name : "URL" , value : "http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2010&suid=20101027_01");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-220/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-221/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-222/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-223/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-224/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-225/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-226/");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

httpPort = get_http_port(default:80);
if(!httpPort){
  exit(0);
}

sndReq = http_get(item:"/immanager", port:httpPort);
rcvRes = http_send_recv(port:httpPort, data:sndReq);

if((isnull(rcvRes)) || ("Symantec :: IM Manager" >!< rcvRes)){
  exit(0);
}

imVer = get_kb_item("Symantec/IM/Manager");
if(!imVer){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"8.4.16")) { 
  security_message(port:httpPort);
  exit(0);
}

exit(0);

