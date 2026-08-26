import AppKit
import SwiftUI

@MainActor
struct ContentView: View {
    private enum LoginField: Hashable {
        case username
        case password
    }

    @ObservedObject var model: StoreViewModel
    @ObservedObject private var processes: StoreProcessManager
    @State private var showsPassword = false
    @State private var loginToast: String?
    @FocusState private var focusedLoginField: LoginField?

    init(model: StoreViewModel) {
        self.model = model
        _processes = ObservedObject(wrappedValue: model.processes)
    }

    var body: some View {
        Group {
            if model.isAuthenticated {
                authenticatedStoreView
            } else {
                loginView
            }
        }
        .font(.title3)
        .controlSize(.large)
        .frame(
            minWidth: model.isAuthenticated ? 960 : 0,
            minHeight: model.isAuthenticated ? 620 : 0
        )
        .background(BrandPalette.mist)
        .overlay(alignment: .top) {
            if !model.isAuthenticated, let loginToast {
                Text(loginToast)
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(BrandPalette.white)
                    .padding(.horizontal, 18)
                    .padding(.vertical, 10)
                    .background(BrandPalette.navy.opacity(0.94))
                    .clipShape(Capsule())
                    .padding(.top, 22)
                    .transition(.move(edge: .top).combined(with: .opacity))
            }
        }
        .onChange(of: model.statusText) { status in
            showLoginToast(for: status)
        }
    }

    private var loginView: some View {
        ZStack {
            BrandPalette.navy.ignoresSafeArea()
            Circle()
                .fill(BrandPalette.blue.opacity(0.20))
                .frame(width: 520, height: 520)
                .offset(x: 390, y: -250)
            Circle()
                .fill(BrandPalette.aqua.opacity(0.16))
                .frame(width: 360, height: 360)
                .offset(x: -430, y: 270)

            BrandCard {
                VStack(spacing: 0) {
                    BrandSymbolImage(asset: .appSymbol)
                        .frame(width: 86, height: 86)
                        .accessibilityLabel("澜序品牌标志")
                    Text("澜序")
                        .font(.system(size: 33, weight: .bold))
                        .foregroundStyle(BrandPalette.navy)
                        .padding(.top, 14)
                    Text("IDENGRID CLOUD BROWSER")
                        .font(.system(size: 13, weight: .semibold))
                        .tracking(2.2)
                        .foregroundStyle(BrandPalette.blue)
                        .padding(.top, 6)
                    Text("环境独立，协作从容")
                        .font(.system(size: 16))
                        .foregroundStyle(BrandPalette.slate)
                        .padding(.top, 12)

                    VStack(spacing: 12) {
                        TextField("用户名", text: $model.username)
                            .font(.system(size: 16))
                            .textFieldStyle(.plain)
                            .focused($focusedLoginField, equals: .username)
                            .brandLoginField(isFocused: focusedLoginField == .username)
                        Group {
                            if showsPassword {
                                TextField("密码", text: $model.password)
                            } else {
                                SecureField("密码", text: $model.password)
                            }
                        }
                        .font(.system(size: 16))
                        .textFieldStyle(.plain)
                        .focused($focusedLoginField, equals: .password)
                        .brandLoginField(
                            isFocused: focusedLoginField == .password,
                            hasTrailingAccessory: true
                        )
                        .overlay(alignment: .trailing) {
                            Button {
                                showsPassword.toggle()
                            } label: {
                                Image(systemName: showsPassword ? "eye.slash" : "eye")
                                    .foregroundStyle(BrandPalette.slate)
                            }
                            .buttonStyle(.plain)
                            .padding(.trailing, 10)
                            .accessibilityLabel(showsPassword ? "隐藏密码" : "显示密码")
                        }
                    }
                    .padding(.top, 24)

                    Button {
                        Task { await model.login() }
                    } label: {
                        Text(LoginPresentation.buttonTitle(isBusy: model.isBusy))
                    }
                    .buttonStyle(BrandLoginButtonStyle())
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.isBusy)
                    .padding(.top, 20)

                    Group {
                        if let status = LoginPresentation.inlineStatus(
                            model.statusText,
                            isBusy: model.isBusy
                        ) {
                            Text(status)
                        } else {
                            Text(" ")
                                .accessibilityHidden(true)
                        }
                    }
                    .font(.system(size: 15))
                    .foregroundStyle(
                        model.statusText.hasPrefix("登录失败")
                            || model.statusText.hasPrefix("请输入")
                            || model.statusText == "用户名或者密码错误"
                            ? Color.red
                            : BrandPalette.slate
                    )
                    .frame(height: 22)
                    .padding(.top, 10)

                    Button("退出应用") {
                        NSApp.terminate(nil)
                    }
                    .buttonStyle(.plain)
                    .font(.system(size: 15))
                    .foregroundStyle(BrandPalette.slate)
                    .padding(.top, 14)
                }
                .frame(maxWidth: .infinity)
            }
            .padding(.horizontal, 16)
            .frame(maxWidth: 464)
        }
    }

    private var authenticatedStoreView: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(BrandPalette.white)
                        .frame(width: 50, height: 50)
                    BrandSymbolImage(asset: .appSymbol)
                        .frame(width: 42, height: 42)
                }
                .accessibilityLabel("IdenGrid 品牌标志")
                VStack(alignment: .leading, spacing: 2) {
                    Text("IdenGrid")
                        .font(.title2.bold())
                        .foregroundStyle(BrandPalette.white)
                    Text("云端店铺工作空间")
                        .font(.subheadline)
                        .foregroundStyle(BrandPalette.white.opacity(0.72))
                }
                Spacer()
                Button("刷新") { Task { await model.listStores() } }
                    .buttonStyle(BrandHeaderButtonStyle())
                Button("退出全部") { model.processes.quitAll() }
                    .buttonStyle(BrandHeaderButtonStyle())
                Button("退出登录") { Task { await model.signOut() } }
                    .buttonStyle(BrandHeaderButtonStyle())
                Button("退出应用") {
                    NSApp.terminate(nil)
                }
                .buttonStyle(BrandHeaderButtonStyle())
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 18)
            .background(BrandPalette.navy)

            VStack(spacing: 16) {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(BrandPalette.blue)
                    TextField("搜索店铺", text: $model.searchText)
                        .textFieldStyle(.plain)
                        .foregroundStyle(BrandPalette.ink)
                        .onChange(of: model.searchText) { _ in model.applySearch() }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(BrandPalette.white)
                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(BrandPalette.blue.opacity(0.16), lineWidth: 1)
                }

                List(model.stores) { store in
                    HStack(spacing: 16) {
                        RoundedRectangle(cornerRadius: 4, style: .continuous)
                            .fill(Color(storeIdentity: try? StoreVisualIdentity(store: store)))
                            .frame(width: 8, height: 54)
                            .accessibilityLabel("店铺颜色标记")
                        Circle()
                            .fill(processes.states[store.id] == .running ? BrandPalette.aqua : BrandPalette.slate.opacity(0.45))
                            .frame(width: 12, height: 12)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 7) {
                            Text(store.name)
                                .font(.title2)
                                .bold()
                                .foregroundStyle(BrandPalette.ink)
                            Text("节点：\(store.nodeName) · 固定IP：\(store.expectedPublicIPv4 ?? "待配置")")
                                .font(.title3)
                                .foregroundStyle(BrandPalette.slate)
                            Text(
                                StoreLatencyLine.text(
                                    store: store,
                                    launchState: processes.states[store.id, default: .idle],
                                    edgeLatency: processes.edgeLatencies[store.id]
                                )
                            )
                            .font(.title3)
                            .foregroundStyle(BrandPalette.slate)
                            Text(processes.states[store.id, default: .idle].chineseLabel)
                                .font(.title3)
                                .fontWeight(.semibold)
                                .foregroundStyle(processes.states[store.id] == .running ? BrandPalette.aqua : BrandPalette.blue)
                        }
                        Spacer()
                        if processes.states[store.id] == .running {
                            Button("打开") { processes.activate(storeID: store.id) }
                                .buttonStyle(BrandPrimaryButtonStyle())
                        } else {
                            Button("启动") { Task { await model.launch(store) } }
                                .buttonStyle(BrandPrimaryButtonStyle())
                                .disabled(
                                    processes.states[store.id, default: .idle].isLaunchInProgress
                                        || !store.enabled
                                        || store.healthStatus != "online"
                                )
                        }
                        Button("关闭") { model.close(store) }
                            .buttonStyle(BrandStoreCloseButtonStyle())
                            .disabled(processes.states[store.id] != .running)
                    }
                    .padding(.vertical, 10)
                    .listRowBackground(BrandPalette.white)
                }
                .scrollContentBackground(.hidden)

                statusLine
            }
            .padding(24)
        }
    }

    private func showLoginToast(for status: String) {
        guard let message = LoginPresentation.toastMessage(status) else { return }
        withAnimation { loginToast = message }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(LoginPresentation.toastDurationSeconds))
            guard loginToast == message else { return }
            withAnimation { loginToast = nil }
        }
    }

    private var statusLine: some View {
        HStack {
            if model.isBusy { ProgressView().tint(BrandPalette.aqua) }
            Text(model.statusText).foregroundStyle(BrandPalette.slate)
        }
    }
}

private extension Color {
    init(storeIdentity: StoreVisualIdentity?) {
        let value = storeIdentity?.color ?? BrandPaletteHex.slate
        var rgb: UInt64 = 0
        Scanner(string: String(value.dropFirst())).scanHexInt64(&rgb)
        self.init(
            red: Double((rgb >> 16) & 0xff) / 255,
            green: Double((rgb >> 8) & 0xff) / 255,
            blue: Double(rgb & 0xff) / 255
        )
    }
}
