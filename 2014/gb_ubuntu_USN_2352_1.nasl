###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2352_1.nasl 7957 2017-12-01 06:40:08Z santu $
#
# Ubuntu Update for dbus USN-2352-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841972");
  script_version("$Revision: 7957 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:40:08 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-09-23 05:53:39 +0200 (Tue, 23 Sep 2014)");
  script_cve_id("CVE-2014-3635", "CVE-2014-3636", "CVE-2014-3637", "CVE-2014-3638",
                "CVE-2014-3639");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for dbus USN-2352-1");
  script_tag(name: "insight", value: "Simon McVittie discovered that DBus
incorrectly handled the file descriptors message limit. A local attacker
could use this issue to cause DBus to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue only applied to
Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-3635)

Alban Crequy discovered that DBus incorrectly handled a large number of
file descriptor messages. A local attacker could use this issue to cause
DBus to stop responding, resulting in a denial of service. This issue only
applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-3636)

Alban Crequy discovered that DBus incorrectly handled certain file
descriptor messages. A local attacker could use this issue to cause DBus
to maintain persistent connections, possibly resulting in a denial of
service. This issue only applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-3637)

Alban Crequy discovered that DBus incorrectly handled a large number of
parallel connections and parallel message calls. A local attacker could use
this issue to cause DBus to consume resources, possibly resulting in a
denial of service. (CVE-2014-3638)

Alban Crequy discovered that DBus incorrectly handled incomplete
connections. A local attacker could use this issue to cause DBus to fail
legitimate connection attempts, resulting in a denial of service.
(CVE-2014-3639)");
  script_tag(name: "affected", value: "dbus on Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name: "USN", value: "2352-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2352-1/");
  script_summary("Check for the Version of dbus");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"dbus", ver:"1.6.18-0ubuntu4.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdbus-1-3:i386", ver:"1.6.18-0ubuntu4.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdbus-1-3:amd64", ver:"1.6.18-0ubuntu4.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"dbus", ver:"1.4.18-1ubuntu1.6", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.4.18-1ubuntu1.6", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"dbus", ver:"1.2.16-2ubuntu4.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.2.16-2ubuntu4.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
