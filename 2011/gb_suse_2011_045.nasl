###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for NetworkManager, wpa_supplicant, NetworkManager-gnome SUSE-SA:2011:045
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "When 802.11X authentication is used (ie WPA Enterprise)
  NetworkManager did not pin a certificate's subject to an ESSID. A
  rogue access point could therefore be used to conduct MITM attacks
  by using any other valid certificate issued by the same CA as used
  in the original network CVE-2006-7246. If password based
  authentication is used (e.g. via PEAP or EAP-TTLS) this means an
  attacker could sniff and potentially crack the password hashes of
  the victims.

  The certificate checks are only performed on newly created
  connections. Users must therefore delete and re-create any existing
  WPA Enterprise connections using e.g. nm-connection-editor to take
  advantage of the checks.

  knetworkmanager is also affected by but a fix is currently not
  available. Users of knetworkmanager are advised to use nm-applet for
  802.11X networks instead.

  The following document gives a more detailed explanation about the
  problem in general. Administrators are advised to take the
  opportunity to review security of their wireless networks if 802.11X
  authentication is used.
  http://www.suse.de/~lnussel/The_Evil_Twin_problem_with_WPA2-Enterprise_v1.1.pdf";
tag_solution = "Please Install the Updated Packages.";

tag_impact = "man in the middle";
tag_affected = "NetworkManager, wpa_supplicant, NetworkManager-gnome on openSUSE 11.3, openSUSE 11.4";


if(description)
{
  script_id(850172);
  script_version("$Revision: 8041 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 08:28:21 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-12-05 12:16:08 +0530 (Mon, 05 Dec 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "SUSE-SA", value: "2011-045");
  script_cve_id("CVE-2006-7246");
  script_name("SuSE Update for NetworkManager, wpa_supplicant, NetworkManager-gnome SUSE-SA:2011:045");

  script_summary("Check for the Version of NetworkManager, wpa_supplicant, NetworkManager-gnome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~0.8.2~15.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-devel", rpm:"NetworkManager-devel~0.8.2~15.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-doc", rpm:"NetworkManager-doc~0.8.2~15.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~0.8.2~15.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-gnome", rpm:"NetworkManager-gnome~0.8.2~9.12.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~0.7.3~3.4.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant-gui", rpm:"wpa_supplicant-gui~0.7.3~3.4.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.3")
{

  if ((res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~0.8~8.13.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-devel", rpm:"NetworkManager-devel~0.8~8.13.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-doc", rpm:"NetworkManager-doc~0.8~8.13.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~0.8~8.13.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-gnome", rpm:"NetworkManager-gnome~0.8~6.3.2", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~0.7.1~5.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant-gui", rpm:"wpa_supplicant-gui~0.7.1~5.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
