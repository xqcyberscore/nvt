###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opensc_sec_bypass_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# OpenSC Security Bypass Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800370");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-03-16 10:38:04 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-0368");
  script_bugtraq_id(33922);
  script_name("OpenSC Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34052");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48958");
  script_xref(name:"URL", value:"http://www.opensc-project.org/pipermail/opensc-announce/2009-February/000023.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_opensc_detect.nasl");
  script_mandatory_keys("OpenSC/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to access data objects
  which are intended to be private.");
  script_tag(name:"affected", value:"OpenSC version prior to 0.11.7 on Linux.");
  script_tag(name:"insight", value:"Security issue due to OpenSC incorrectly initializing private data objects.
  This can be exploited to access data objects which are intended to be
  private through low level APDU commands or debugging tool.");
  script_tag(name:"solution", value:"Upgrade to OpenSC version 0.11.7
  http://www.opensc-project.org/files/opensc");
  script_tag(name:"summary", value:"This host is installed with OpenSC and is prone to security bypass
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

openscVer = get_kb_item("OpenSC/Ver");
if(openscVer != NULL)
{
  if(version_is_less(version:openscVer, test_version:"0.11.7")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
