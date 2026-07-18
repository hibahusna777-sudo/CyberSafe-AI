import streamlit as st


def render_password_tools():
    st.title("🔐 Password Security Hub")

    st.write("Check your password security level.")

    password = st.text_input(
        "Enter Password",
        type="password"
    )

    if st.button("Check Password"):

        if password == "":
            st.warning("Please enter a password")

        elif len(password) < 8:
            st.error("❌ Weak Password - Use at least 8 characters")

        else:
            st.success("✅ Strong Password")

