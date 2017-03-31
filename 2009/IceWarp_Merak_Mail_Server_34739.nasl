###############################################################################
# OpenVAS Vulnerability Test
# $Id: IceWarp_Merak_Mail_Server_34739.nasl 4970 2017-01-09 15:00:59Z teissa $
#
# IceWarp Merak Mail Server 'Base64FileEncode()' Stack-Based Buffer Overflow Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "IceWarp Merak Mail Server s prone to a stack-based buffer-overflow
   vulnerability because the application fails to bounds-check
   user-supplied data before copying it into an insufficiently sized
   buffer.

   An attacker could exploit this issue to execute arbitrary code in
   the context of the affected application. Failed exploit attempts
   will likely result in denial-of-service conditions.

   IceWarp Merak Mail Server 9.4.1 is vulnerable; other versions may
   also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100168";
CPE = "cpe:/a:icewarp:merak_mail_server";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 4970 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-09 16:00:59 +0100 (Mon, 09 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-1516");
 script_bugtraq_id(34739);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("SMTP problems");
  script_name("IceWarp Merak Mail Server 'Base64FileEncode()' Stack-Based Buffer Overflow Vulnerability");


  script_tag(name:"qod_type", value:"remote_banner");
  script_dependencies("gb_merak_mail_server_detect.nasl");
  script_require_keys("MerakMailServer/Ver");
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34739");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

merakVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port);
if(merakVer == NULL){
  exit(0);
} 
 
if(version_is_less_equal(version:merakVer, test_version:"9.4.1")){
  security_message(port:port);
}
