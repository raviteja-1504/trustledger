import { analyzeFile } from "@/lib/scanner";

describe("BOLA: authenticated identity ignored at a write sink (found via real-world VAmPI testing)", () => {
  it("flags VAmPI's real vulnerable update_password branch", () => {
    const content = `
def update_password(username):
    request_data = request.get_json()
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        if request_data.get('password'):
            if vuln:
                user = User.query.filter_by(username=username).first()
                if user:
                    user.password = request_data.get('password')
                    db.session.commit()
`;
    const result = analyzeFile("api_views/users.py", content);
    const finding = result.indicators.find(i => i.id === "bola-identity-mismatch");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
    expect(finding?.detail).toContain("resp");
    expect(finding?.detail).toContain("username");
  });

  it("does not flag VAmPI's real safe branch (filter_by keyed off the auth response)", () => {
    const content = `
def update_password(username):
    request_data = request.get_json()
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        if request_data.get('password'):
            user = User.query.filter_by(username=resp['sub']).first()
            user.password = request_data.get('password')
            db.session.commit()
`;
    const result = analyzeFile("api_views/users.py", content);
    expect(result.indicators.some(i => i.id === "bola-identity-mismatch")).toBe(false);
  });

  it("does not flag a legitimately admin-gated action on another user's identifier", () => {
    const content = `
def admin_delete_user(username):
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        current = User.query.filter_by(username=resp['sub']).first()
        if current.admin:
            deleted = User.query.filter_by(username=username).delete()
            db.session.commit()
`;
    const result = analyzeFile("api_views/users.py", content);
    expect(result.indicators.some(i => i.id === "bola-identity-mismatch")).toBe(false);
  });

  it("does not flag when the sink is explicitly compared against the authenticated identity", () => {
    const content = `
def update_profile(target_username):
    resp = token_validator(request.headers.get('Authorization'))
    if target_username != resp['sub']:
        return Response("Forbidden", 403)
    user = User.query.filter_by(username=target_username).first()
    user.bio = request_data.get('bio')
`;
    const result = analyzeFile("api_views/users.py", content);
    expect(result.indicators.some(i => i.id === "bola-identity-mismatch")).toBe(false);
  });

  it("flags the equivalent JS/Mongoose shape: auth established, then a route param drives the write", () => {
    const content = `
async function updatePassword(req, res) {
  const decoded = jwt.verify(req.headers.authorization, SECRET);
  const newPassword = req.body.password;
  await User.findByIdAndUpdate(req.params.id, { password: newPassword });
  res.json({ status: "ok" });
}
module.exports = updatePassword;
`;
    const result = analyzeFile("routes/users.js", content);
    const finding = result.indicators.find(i => i.id === "bola-identity-mismatch");
    expect(finding).toBeDefined();
  });
});
