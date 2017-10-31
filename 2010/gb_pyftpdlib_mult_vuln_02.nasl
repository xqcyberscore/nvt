###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pyftpdlib_mult_vuln_02.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# pyftpdlib FTP Server Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to retrieve or upload arbitrary
  system files or cause a denial of service.
  Impact Level: Application/System";
tag_affected = "ftpserver.py in pyftpdlib before 0.2.0";
tag_insight = "Multiple flaws exist because pyftpdlib,
  - allows remote authenticated users to access arbitrary files and directories
    via a .. (dot dot) in a LIST, STOR, or RETR command.
  - does not increment the attempted_logins count for a USER command that
    specifies an invalid username, which makes it easier for remote attackers
    to obtain access via a brute-force attack.
  - allows remote attackers to cause a denial of service via a long command.
  - does not limit the number of attempts to discover a unique filename, which
    might allow remote authenticated users to cause a denial of service via
    a STOU command.
  - does not prevent TCP connections to privileged ports if the destination IP
    address matches the source IP address of the connection from the FTP client,
    which might allow remote authenticated users to conduct FTP bounce attacks
    via crafted FTP data.";
tag_solution = "Upgrade to pyftpdlib version 0.5.2 or later,
  For updates refer to http://code.google.com/p/pyftpdlib/downloads/list";
tag_summary = "This host is running pyftpdlib FTP server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801617);
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2007-6736", "CVE-2007-6737", "CVE-2007-6739",
                "CVE-2007-6740", "CVE-2007-6741");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("pyftpdlib FTP Server Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://code.google.com/p/pyftpdlib/issues/detail?id=3");
  script_xref(name : "URL" , value : "http://code.google.com/p/pyftpdlib/issues/detail?id=9");
  script_xref(name : "URL" , value : "http://code.google.com/p/pyftpdlib/issues/detail?id=11");
  script_xref(name : "URL" , value : "http://code.google.com/p/pyftpdlib/issues/detail?id=20");
  script_xref(name : "URL" , value : "http://code.google.com/p/pyftpdlib/issues/detail?id=25");
  script_xref(name : "URL" , value : "http://code.google.com/p/pyftpdlib/source/browse/trunk/HISTORY");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_pyftpdlib_detect.nasl");
  script_mandatory_keys("pyftpdlib/Ver");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);

  exit(0);
}


include("version_func.inc");

## Get version from KB
ver = get_kb_item("pyftpdlib/Ver");

if(ver != NULL)
{
  ## Check for pyftpdlib version < 0.2.0
  if(version_is_less(version:ver, test_version:"0.2.0")) {
     security_message(port:0);
  }
}
