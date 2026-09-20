import {
  findS3PublicAcl, findOpenIngress, findUnencryptedStorage, findIamWildcard, findPublicDb,
  extractHclResourceBlocks,
} from "@/lib/iacTerraform";

describe("iacTerraform.findS3PublicAcl", () => {
  it("flags a public-read ACL", () => {
    const content = `
resource "aws_s3_bucket_acl" "x" {
  bucket = aws_s3_bucket.x.id
  acl    = "public-read"
}
`;
    expect(findS3PublicAcl(content).some(f => f.id === "iac-s3-public-acl")).toBe(true);
  });

  it("flags a public-read-write ACL", () => {
    const content = `acl = "public-read-write"`;
    expect(findS3PublicAcl(content).some(f => f.id === "iac-s3-public-acl")).toBe(true);
  });

  it("does not flag a private ACL", () => {
    const content = `acl = "private"`;
    expect(findS3PublicAcl(content)).toHaveLength(0);
  });
});

describe("iacTerraform.findOpenIngress", () => {
  it("flags an ingress rule open to 0.0.0.0/0", () => {
    const content = `
resource "aws_security_group" "x" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;
    expect(findOpenIngress(content).some(f => f.id === "iac-open-ingress")).toBe(true);
  });

  it("flags the standalone aws_security_group_rule ingress shape", () => {
    const content = `
resource "aws_security_group_rule" "x" {
  type        = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}
`;
    expect(findOpenIngress(content).some(f => f.id === "iac-open-ingress")).toBe(true);
  });

  it("does not flag an otherwise-identical egress rule", () => {
    const content = `
resource "aws_security_group" "x" {
  egress {
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;
    expect(findOpenIngress(content)).toHaveLength(0);
  });

  it("does not flag a scoped CIDR block", () => {
    const content = `
resource "aws_security_group" "x" {
  ingress {
    cidr_blocks = ["10.0.0.0/16"]
  }
}
`;
    expect(findOpenIngress(content)).toHaveLength(0);
  });
});

describe("iacTerraform.extractHclResourceBlocks", () => {
  it("finds a resource block's line range via brace depth", () => {
    const lines = [
      'resource "aws_s3_bucket" "a" {',
      "  bucket = \"a\"",
      "}",
      'resource "aws_s3_bucket" "b" {',
      "  bucket = \"b\"",
      "  tags = {",
      '    Name = "b"',
      "  }",
      "}",
    ];
    const blocks = extractHclResourceBlocks(lines, "aws_s3_bucket");
    expect(blocks).toHaveLength(2);
    expect(blocks[0]).toMatchObject({ name: "a", start: 0, end: 2 });
    expect(blocks[1]).toMatchObject({ name: "b", start: 3, end: 8 });
  });
});

describe("iacTerraform.findUnencryptedStorage", () => {
  it("flags an S3 bucket with no encryption configured anywhere", () => {
    const content = `
resource "aws_s3_bucket" "x" {
  bucket = "my-bucket"
}
`;
    const findings = findUnencryptedStorage(content);
    expect(findings.some(f => f.id === "iac-unencrypted-storage" && f.detail.includes("x"))).toBe(true);
  });

  it("does not flag a bucket with an inline encryption block (pre-v4 provider style)", () => {
    const content = `
resource "aws_s3_bucket" "x" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
  }
}
`;
    expect(findUnencryptedStorage(content)).toHaveLength(0);
  });

  it("does not flag a bucket referenced by a separate encryption-config resource (v4+ provider style)", () => {
    const content = `
resource "aws_s3_bucket" "x" {
  bucket = "my-bucket"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "x" {
  bucket = aws_s3_bucket.x.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}
`;
    expect(findUnencryptedStorage(content)).toHaveLength(0);
  });

  it("flags an RDS instance with no storage_encrypted = true", () => {
    const content = `
resource "aws_db_instance" "x" {
  engine = "postgres"
}
`;
    expect(findUnencryptedStorage(content).some(f => f.detail.includes("RDS"))).toBe(true);
  });

  it("does not flag an RDS instance with storage_encrypted = true", () => {
    const content = `
resource "aws_db_instance" "x" {
  storage_encrypted = true
}
`;
    expect(findUnencryptedStorage(content)).toHaveLength(0);
  });
});

describe("iacTerraform.findIamWildcard", () => {
  it("flags a JSON-style wildcard Action", () => {
    const content = `"Action": "*"`;
    expect(findIamWildcard(content).some(f => f.id === "iac-iam-wildcard")).toBe(true);
  });

  it("flags an HCL-style wildcard resources list", () => {
    const content = `resources = ["*"]`;
    expect(findIamWildcard(content).some(f => f.id === "iac-iam-wildcard")).toBe(true);
  });

  it("does not flag a scoped action list", () => {
    const content = `actions = ["s3:GetObject"]`;
    expect(findIamWildcard(content)).toHaveLength(0);
  });
});

describe("iacTerraform.findPublicDb", () => {
  it("flags a publicly_accessible RDS instance", () => {
    const content = `
resource "aws_db_instance" "x" {
  publicly_accessible = true
}
`;
    expect(findPublicDb(content).some(f => f.id === "iac-public-db")).toBe(true);
  });

  it("does not flag a private RDS instance", () => {
    const content = `
resource "aws_db_instance" "x" {
  publicly_accessible = false
}
`;
    expect(findPublicDb(content)).toHaveLength(0);
  });
});
