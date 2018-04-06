###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_colasoft_capsa_snmp_dos_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Colasoft Capsa Malformed SNMP V1 Packet Remote Denial of Service Vulnerability
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

tag_impact = "Successful exploitation could allow remote attackers to crash
the affected application, denying service to legitimate users.

Impact Level: Application";

tag_affected = "Colasoft Capsa Version 7.2.1 and prior.";

tag_insight = "The flaw is due to an unspecified error within the SNMPv1
protocol dissector and can be exploited to cause a crash via a specially
crafted packet.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Colasoft Capsa and is prone to denial
of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902570");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_bugtraq_id(49621);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Colasoft Capsa Malformed SNMP V1 Packet Remote Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46034");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519630");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2011-09/0088.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm Colasoft Capsa
key = "SOFTWARE\Colasoft\Colasoft Capsa 7 Enterprise Demo Edition";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get Version From Registry
version = registry_get_sz(key:key, item:"Version");
if(version)
{
 ## Check for Colasoft Capsa Version 7.2.1 and prior
 if(version_is_less_equal(version:version, test_version:"7.2.1.2299")) {
    security_message(0);
  }
}
