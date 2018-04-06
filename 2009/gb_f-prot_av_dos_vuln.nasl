###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f-prot_av_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# F-PROT AV 'ELF' Header Denial of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to bypass anti-virus protection
  and cause a Denial of Service condition.
  Impact Level: Application";
tag_affected = "Frisk Software, F-Prot Antivirus version 4.6.8 and prior on Linux.";
tag_insight = "The flaw is due to error in ELF program with a corrupted header. The
  scanner can be exploited while scanning the header.";
tag_solution = "Upgrade to F-Prot Antivirus version 6.0.2 or later.
  For updates refer to http://www.f-prot.com/index.html";
tag_summary = "This host has F-PROT Antivirus installed and is prone to Denial of
  Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800325");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-13 15:40:34 +0100 (Tue, 13 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5747");
  script_bugtraq_id(32753);
  script_name("F-PROT AV 'ELF' Header Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://securityreason.com/securityalert/4822");
  script_xref(name : "URL" , value : "http://www.ivizsecurity.com/security-advisory-iviz-sr-08016.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_f-prot_av_detect_lin.nasl");
  script_mandatory_keys("F-Prot/AV/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

fpscanVer = get_kb_item("F-Prot/AV/Linux/Ver");
if(!fpscanVer){
  exit(0);
}

# Check for version <= 4.6.8
if(version_is_less_equal(version:fpscanVer, test_version:"4.6.8")){
  security_message(0);
}
