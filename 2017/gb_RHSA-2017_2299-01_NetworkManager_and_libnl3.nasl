###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2299-01_NetworkManager_and_libnl3.nasl 6855 2017-08-04 13:23:41Z cfischer $
#
# RedHat Update for NetworkManager and libnl3 RHSA-2017:2299-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871848");
  script_version("$Revision: 6855 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-04 15:23:41 +0200 (Fri, 04 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:47:51 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2017-0553");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for NetworkManager and libnl3 RHSA-2017:2299-01");
  script_tag(name: "summary", value: "Check the version of NetworkManager and libnl3");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "NetworkManager is a system network service 
  that manages network devices and connections, attempting to keep active network 
  connectivity when available. Its capabilities include managing Ethernet, 
  wireless, mobile broadband (WWAN), and PPPoE devices, as well as providing VPN 
  integration with a variety of different VPN services. The libnl3 packages 
  contain a convenience library that simplifies using the Linux kernel's Netlink 
  sockets interface for network manipulation. The following packages have been 
  upgraded to a later upstream version: NetworkManager (1.8.0), 
  network-manager-applet (1.8.0). (BZ#1413312, BZ#1414103, BZ#1441621) Security 
  Fix(es) in the libnl3 component: * An integer overflow leading to a heap-buffer 
  overflow was found in the libnl library. An attacker could use this flaw to 
  cause an application compiled with libnl to crash or possibly execute arbitrary 
  code in the context of the user running such an application. (CVE-2017-0553) 
  Additional Changes: For detailed information on changes in this release, see the 
  Red Hat Enterprise Linux 7.4 Release Notes linked from the References section. 
  "); 
  script_tag(name: "affected", value: "NetworkManager and libnl3 on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:2299-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-August/msg00003.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"NetworkManager-config-server", rpm:"NetworkManager-config-server~1.8.0~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~1.8.0~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-adsl", rpm:"NetworkManager-adsl~1.8.0~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-bluetooth", rpm:"NetworkManager-bluetooth~1.8.0~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-debuginfo", rpm:"NetworkManager-debuginfo~1.8.0~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~1.8.0~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-libnm", rpm:"NetworkManager-libnm~1.8.0~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan", rpm:"NetworkManager-libreswan~1.2.4~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan-debuginfo", rpm:"NetworkManager-libreswan-debuginfo~1.2.4~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan-gnome", rpm:"NetworkManager-libreswan-gnome~1.2.4~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-ppp", rpm:"NetworkManager-ppp~1.8.0~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-team", rpm:"NetworkManager-team~1.8.0~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-tui", rpm:"NetworkManager-tui~1.8.0~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-wifi", rpm:"NetworkManager-wifi~1.8.0~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-wwan", rpm:"NetworkManager-wwan~1.8.0~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnl3", rpm:"libnl3~3.2.28~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnl3-cli", rpm:"libnl3-cli~3.2.28~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnl3-debuginfo", rpm:"libnl3-debuginfo~3.2.28~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnm-gtk", rpm:"libnm-gtk~1.8.0~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnma", rpm:"libnma~1.8.0~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"network-manager-applet-debuginfo", rpm:"network-manager-applet-debuginfo~1.8.0~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nm-connection-editor", rpm:"nm-connection-editor~1.8.0~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}