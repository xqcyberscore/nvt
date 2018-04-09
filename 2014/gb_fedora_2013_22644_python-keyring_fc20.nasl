###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for python-keyring FEDORA-2013-22644
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

include("revisions-lib.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.867343");
  script_version("$Revision: 9373 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:57:18 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-02-03 19:50:56 +0530 (Mon, 03 Feb 2014)");
  script_cve_id("CVE-2012-4571");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Update for python-keyring FEDORA-2013-22644");

  tag_insight = "The Python keyring lib provides a easy way to access the system keyring
service from python. It can be used in any application that needs safe
password storage.

The keyring services supported by the Python keyring lib:

* **OSXKeychain**: supports the Keychain service in Mac OS X.
* **KDEKWallet**: supports the KDE's Kwallet service.
* **GnomeKeyring**: for Gnome 2 environment.
* **SecretServiceKeyring**: for newer GNOME and KDE environments.
* **WinVaultKeyring**: supports the Windows Credential Vault

Besides these native password storing services provided by operating systems.
Python keyring lib also provides following build-in keyrings.

* **Win32CryptoKeyring**: for Windows 2k+.
* **CryptedFileKeyring**: a command line interface keyring base on PyCrypto.
* **UncryptedFileKeyring**: a keyring which leaves passwords directly in file.
";

  tag_affected = "python-keyring on Fedora 20";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "FEDORA", value: "2013-22644");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-December/123835.html");
  script_tag(name:"summary", value:"Check for the Version of python-keyring");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC20")
{

  if ((res = isrpmvuln(pkg:"python-keyring", rpm:"python-keyring~3.3~1.fc20", rls:"FC20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}