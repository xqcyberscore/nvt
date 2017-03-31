###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xerox_colorqube_60844.nasl 3911 2016-08-30 13:08:37Z mime $
#
# Xerox ColorQube Multiple Unspecified Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103806";
CPE = "cpe:/h:xerox:colorqube";

tag_affected = "Xerox ColorQube 9303
Xerox ColorQube 9302
Xerox ColorQube 9301

with System Software < 071.180.203.06400";

tag_summary = "Xerox ColorQube is prone to multiple unspecified security vulnerabilities.";

tag_solution = "Updates are available. Please see the references or vendor advisory
for more information.";

tag_vuldetect = "Check the System Software version";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(60844);
 script_version ("$Revision: 3911 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Xerox WorkCentre/ColorQube Multiple Unspecified Security Vulnerabilities");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60844");
 script_xref(name:"URL", value:"http://www.xerox.com");
 script_xref(name:"URL", value:"http://www.xerox.com/download/security/security-bulletin/18344-4e02474da251c/cert_XRX13-006_v1.2.pdf");
 
 script_tag(name:"last_modification", value:"$Date: 2016-08-30 15:08:37 +0200 (Tue, 30 Aug 2016) $");
 script_tag(name:"creation_date", value:"2013-10-11 11:54:40 +0200 (Fri, 11 Oct 2013)");
 script_summary("Determine if System Software is < 071.180.203.06400");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("General");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_xerox_printer_detect.nasl","gb_snmp_sysdesc.nasl");
 script_mandatory_keys("xerox_model","SNMP/sysdesc");

 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("version_func.inc");

model = get_kb_item("xerox_model");

if(!model || model !~ "^ColorQube 930[1-3]")exit(0);

sysdesc = get_kb_item("SNMP/sysdesc");
if(!sysdesc || "System Software" >!< sysdesc)exit(0);

version = eregmatch(pattern:"System Software ([^,]+),", string:sysdesc);
if(isnull(version[1]))exit(0);

vers = version[1];

if(version_is_less(version:vers, test_version:"071.180.203.06400")) {

  security_message(0);
  exit(0);

}  

exit(99);

