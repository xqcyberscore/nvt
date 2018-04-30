###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1851_1.nasl 9650 2018-04-27 08:51:00Z cfischer $
#
# Ubuntu Update for python-keystoneclient USN-1851-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841450");
  script_version("$Revision: 9650 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-27 10:51:00 +0200 (Fri, 27 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-06-04 09:20:23 +0530 (Tue, 04 Jun 2013)");
  script_cve_id("CVE-2013-2104");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_name("Ubuntu Update for python-keystoneclient USN-1851-1");

  script_xref(name: "USN", value: "1851-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1851-1/");
  script_tag(name: "summary" , value: "Check for the Version of python-keystoneclient");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU13\.04");
  script_tag(name : "affected" , value : "python-keystoneclient on Ubuntu 13.04");
  script_tag(name : "insight" , value : "Eoghan Glynn and Alex Meade discovered that python-keystoneclient did not
  properly perform expiry checks for the PKI tokens used in Keystone. If
  Keystone were setup to use PKI tokens (the default in Ubuntu 13.04), a
  previously authenticated user could continue to use a PKI token for longer
  than intended.");
  script_tag(name : "solution" , value : "Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU13.04")
{
  ## Changed package version from 1:0.2.3-0ubuntu2.2 to 1:0.2.3-0ubuntu2
  if ((res = isdpkgvuln(pkg:"python-keystoneclient", ver:"1:0.2.3-0ubuntu2", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
