###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for Java Runtime Environment HPSBUX00267
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Remote unauthorized access";
tag_affected = "Java Runtime Environment on
  Any HP-UX system running the supported HP-UX versions";
tag_insight = "A potential security vulnerability has been identified in the HP-UX Java 
  Runtime Environment (JRE) where the vulnerability may be remotely exploited 
  to create an unauthorized access.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c00958678-1");
  script_id(835136);
  script_version("$Revision: 3220 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-03 15:59:06 +0200 (Tue, 03 May 2016) $");
  script_tag(name:"creation_date", value:"2009-05-05 12:14:23 +0200 (Tue, 05 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "HPSBUX", value: "00267");
  script_name( "HP-UX Update for Java Runtime Environment HPSBUX00267");

  script_summary("Check for the Version of Java Runtime Environment");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("HP-UX Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:hp:hp-ux", "ssh/login/release");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-hpux.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "HPUX11.00")
{

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.2.X", revision:"1.2.2.15", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.2.X", revision:"1.2.2.15", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.2.X", revision:"1.2.2.15", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.3.X", revision:"1.3.1.08", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.3.X", revision:"1.3.1.08", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.3.X", revision:"1.3.1.08", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.4.0", revision:"1.4.0.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.4.0", revision:"1.4.0.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.4.0", revision:"1.4.0.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.4.1", revision:"1.4.1.00", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.4.1", revision:"1.4.1.00", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.4.1", revision:"1.4.1.00", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.22")
{

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.2.X", revision:"1.2.2.15", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.2.X", revision:"1.2.2.15", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.2.X", revision:"1.2.2.15", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.3.X", revision:"1.3.1.08", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.3.X", revision:"1.3.1.08", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.3.X", revision:"1.3.1.08", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.4.0", revision:"1.4.0.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.4.0", revision:"1.4.0.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.4.0", revision:"1.4.0.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.4.1", revision:"1.4.1.00", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.4.1", revision:"1.4.1.00", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.4.1", revision:"1.4.1.00", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.2.X", revision:"1.2.2.15", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.2.X", revision:"1.2.2.15", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.2.X", revision:"1.2.2.15", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.3.X", revision:"1.3.1.08", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.3.X", revision:"1.3.1.08", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.3.X", revision:"1.3.1.08", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.4.0", revision:"1.4.0.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.4.0", revision:"1.4.0.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.4.0", revision:"1.4.0.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.4.1", revision:"1.4.1.00", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.4.1", revision:"1.4.1.00", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.4.1", revision:"1.4.1.00", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.2.X", revision:"1.2.2.15", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.2.X", revision:"1.2.2.15", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.2.X", revision:"1.2.2.15", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.3.X", revision:"1.3.1.08", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.3.X", revision:"1.3.1.08", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.3.X", revision:"1.3.1.08", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.4.0", revision:"1.4.0.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.4.0", revision:"1.4.0.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.4.0", revision:"1.4.0.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JRE 1.4.1", revision:"1.4.1.00", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JDK 1.4.1", revision:"1.4.1.00", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"JPI 1.4.1", revision:"1.4.1.00", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
