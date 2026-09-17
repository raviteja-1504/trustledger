import { analyzeFile } from "@/lib/scanner";

describe("plaintext password storage (found via real-world VAmPI testing)", () => {
  it("flags VAmPI's real unhashed password assignment (request.get_json() taint source)", () => {
    const content = `
def update_password(username):
    request_data = request.get_json()
    resp = token_validator(request.headers.get('Authorization'))
    if request_data.get('password'):
        user = User.query.filter_by(username=resp['sub']).first()
        user.password = request_data.get('password')
        db.session.commit()
`;
    const result = analyzeFile("api_views/users.py", content);
    const finding = result.indicators.find(i => i.id === "plaintext-password-storage");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("flags a direct inline request-attribute assignment even with no named-taint step", () => {
    const content = `
function updateUser(req, res) {
  const user = getUser(req.params.id);
  user.password = req.body.password;
  user.save();
}
module.exports = updateUser;
`;
    const result = analyzeFile("routes/user.js", content);
    expect(result.indicators.some(i => i.id === "plaintext-password-storage")).toBe(true);
  });

  it("does not flag a password assignment that goes through a hashing function", () => {
    const content = `
def register_user(username, password, email):
    hashed = generate_password_hash(password)
    new_user = User(username=username, password=hashed, email=email)
    db.session.add(new_user)
    db.session.commit()
`;
    const result = analyzeFile("models/user_model.py", content);
    expect(result.indicators.some(i => i.id === "plaintext-password-storage")).toBe(false);
  });

  it("does not flag an unrelated attribute assignment with 'password' only in a comment", () => {
    const content = `
def reset_flow():
    # does not touch the password field directly
    user.status = "pending"
    return user
`;
    const result = analyzeFile("models/user_model.py", content);
    expect(result.indicators.some(i => i.id === "plaintext-password-storage")).toBe(false);
  });
});
