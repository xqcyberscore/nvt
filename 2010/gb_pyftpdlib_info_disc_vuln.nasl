###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pyftpdlib_info_disc_vuln.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# pyftpdlib FTP Server Information Disclosure Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to obtain potentially sensitive
  information about the number of in-progress data connections.
  Impact Level: Application";
tag_affected = "ftpserver.py in pyftpdlib before 0.1.1";
tag_insight = "The flaw exists because pyftpdlib does not choose a random value for the port
  associated with the PASV command, which makes it easier for remote attackers
  to obtain potentially sensitive information about the number of in-progress
  data connections by reading the response to this command.";
tag_solution = "Upgrade to pyftpdlib version 0.5.2 or later,
  For updates refer to http://code.google.com/p/pyftpdlib/downloads/list";
tag_summary = "This host is running pyftpdlib FTP server and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_id(801618);
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2007-6738");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("pyftpdlib FTP Server Information Disclosure Vulnerability");
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
  ## Check for pyftpdlib version < 0.1.1
  if(version_is_less(version:ver, test_version:"0.1.1")) {
     security_message(port:0);
  }
}
